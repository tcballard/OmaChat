//! Strict standard geohash encoding and decoding.

use std::{error::Error, fmt, str::FromStr};

/// The standard geohash base32 alphabet.
pub const ALPHABET: &[u8; 32] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// Minimum channel precision accepted by the pinned mobile clients.
pub const MIN_PRECISION: usize = 1;

/// Maximum channel precision accepted by the pinned mobile clients.
pub const MAX_PRECISION: usize = 12;

/// A validated, lowercase geohash.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Geohash(String);

impl Geohash {
    /// Parse a geohash and normalize ASCII uppercase characters to lowercase.
    pub fn parse(value: &str) -> Result<Self, GeohashError> {
        validate_precision(value.len())?;

        let mut normalized = String::with_capacity(value.len());
        for (index, byte) in value.bytes().enumerate() {
            let byte = byte.to_ascii_lowercase();
            if alphabet_value(byte).is_none() {
                return Err(GeohashError::InvalidCharacter { index, byte });
            }
            normalized.push(char::from(byte));
        }

        Ok(Self(normalized))
    }

    /// Return the normalized wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return this geohash's precision in characters.
    #[must_use]
    pub fn precision(&self) -> usize {
        self.0.len()
    }

    /// Decode the latitude and longitude bounds for this cell.
    #[must_use]
    pub fn bounds(&self) -> Bounds {
        let mut bounds = Bounds::WORLD;
        let mut longitude_bit = true;

        for byte in self.0.bytes() {
            let value = alphabet_value(byte).expect("validated geohash alphabet");
            for mask in [16, 8, 4, 2, 1] {
                if longitude_bit {
                    let midpoint = (bounds.longitude_min + bounds.longitude_max) / 2.0;
                    if value & mask == 0 {
                        bounds.longitude_max = midpoint;
                    } else {
                        bounds.longitude_min = midpoint;
                    }
                } else {
                    let midpoint = (bounds.latitude_min + bounds.latitude_max) / 2.0;
                    if value & mask == 0 {
                        bounds.latitude_max = midpoint;
                    } else {
                        bounds.latitude_min = midpoint;
                    }
                }
                longitude_bit = !longitude_bit;
            }
        }

        bounds
    }

    /// Decode the center coordinate for this cell.
    #[must_use]
    pub fn center(&self) -> Coordinate {
        self.bounds().center()
    }
}

impl AsRef<str> for Geohash {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Geohash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Geohash {
    type Err = GeohashError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// A latitude/longitude pair in degrees.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Coordinate {
    pub latitude: f64,
    pub longitude: f64,
}

/// The closed bounds of a geohash cell in degrees.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bounds {
    pub latitude_min: f64,
    pub latitude_max: f64,
    pub longitude_min: f64,
    pub longitude_max: f64,
}

impl Bounds {
    const WORLD: Self = Self {
        latitude_min: -90.0,
        latitude_max: 90.0,
        longitude_min: -180.0,
        longitude_max: 180.0,
    };

    /// Return the center coordinate of these bounds.
    #[must_use]
    pub fn center(self) -> Coordinate {
        Coordinate {
            latitude: (self.latitude_min + self.latitude_max) / 2.0,
            longitude: (self.longitude_min + self.longitude_max) / 2.0,
        }
    }

    /// Report whether a coordinate is inside these closed bounds.
    #[must_use]
    pub fn contains(self, coordinate: Coordinate) -> bool {
        (self.latitude_min..=self.latitude_max).contains(&coordinate.latitude)
            && (self.longitude_min..=self.longitude_max).contains(&coordinate.longitude)
    }
}

/// Encode a coordinate using the standard geohash bit ordering.
pub fn encode(latitude: f64, longitude: f64, precision: usize) -> Result<Geohash, GeohashError> {
    validate_coordinate(latitude, longitude)?;
    validate_precision(precision)?;

    let mut latitude_range = [-90.0, 90.0];
    let mut longitude_range = [-180.0, 180.0];
    let mut longitude_bit = true;
    let mut bit = 0;
    let mut character = 0;
    let mut result = String::with_capacity(precision);

    while result.len() < precision {
        let range = if longitude_bit {
            &mut longitude_range
        } else {
            &mut latitude_range
        };
        let coordinate = if longitude_bit { longitude } else { latitude };
        let midpoint = (range[0] + range[1]) / 2.0;
        if coordinate >= midpoint {
            character |= 1 << (4 - bit);
            range[0] = midpoint;
        } else {
            range[1] = midpoint;
        }
        longitude_bit = !longitude_bit;

        if bit == 4 {
            result.push(char::from(ALPHABET[character]));
            bit = 0;
            character = 0;
        } else {
            bit += 1;
        }
    }

    Ok(Geohash(result))
}

/// Errors returned by strict geohash parsing and encoding.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GeohashError {
    InvalidPrecision { precision: usize },
    InvalidCharacter { index: usize, byte: u8 },
    NonFiniteCoordinate,
    LatitudeOutOfRange { latitude: f64 },
    LongitudeOutOfRange { longitude: f64 },
}

impl fmt::Display for GeohashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrecision { precision } => write!(
                formatter,
                "geohash precision must be {MIN_PRECISION}..={MAX_PRECISION}, got {precision}"
            ),
            Self::InvalidCharacter { index, byte } => write!(
                formatter,
                "invalid geohash byte 0x{byte:02x} at byte index {index}"
            ),
            Self::NonFiniteCoordinate => formatter.write_str("coordinates must be finite"),
            Self::LatitudeOutOfRange { latitude } => {
                write!(formatter, "latitude must be -90..=90, got {latitude}")
            }
            Self::LongitudeOutOfRange { longitude } => {
                write!(formatter, "longitude must be -180..=180, got {longitude}")
            }
        }
    }
}

impl Error for GeohashError {}

fn validate_precision(precision: usize) -> Result<(), GeohashError> {
    if (MIN_PRECISION..=MAX_PRECISION).contains(&precision) {
        Ok(())
    } else {
        Err(GeohashError::InvalidPrecision { precision })
    }
}

fn validate_coordinate(latitude: f64, longitude: f64) -> Result<(), GeohashError> {
    if !latitude.is_finite() || !longitude.is_finite() {
        return Err(GeohashError::NonFiniteCoordinate);
    }
    if !(-90.0..=90.0).contains(&latitude) {
        return Err(GeohashError::LatitudeOutOfRange { latitude });
    }
    if !(-180.0..=180.0).contains(&longitude) {
        return Err(GeohashError::LongitudeOutOfRange { longitude });
    }
    Ok(())
}

fn alphabet_value(byte: u8) -> Option<usize> {
    ALPHABET.iter().position(|candidate| *candidate == byte)
}
