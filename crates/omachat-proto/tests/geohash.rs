use omachat_proto::geohash::{Coordinate, Geohash, GeohashError, MAX_PRECISION, encode};

#[test]
fn matches_public_and_pinned_mobile_cases() {
    assert_eq!(encode(42.6, -5.6, 5).unwrap().as_str(), "ezs42");
    assert_eq!(
        encode(57.649_11, 10.407_44, 11).unwrap().as_str(),
        "u4pruydqqvj"
    );

    for value in ["gcpvj", "r3gx2", "zzzzzz"] {
        let geohash = Geohash::parse(value).unwrap();
        assert_eq!(
            encode(
                geohash.center().latitude,
                geohash.center().longitude,
                geohash.precision()
            )
            .unwrap(),
            geohash
        );
    }
}

#[test]
fn normalizes_only_legal_ascii_case() {
    assert_eq!(Geohash::parse("GCPVJ").unwrap().as_str(), "gcpvj");
    assert_eq!(
        Geohash::parse("gcpvi"),
        Err(GeohashError::InvalidCharacter {
            index: 4,
            byte: b'i'
        })
    );
    assert_eq!(
        Geohash::parse("gc pv"),
        Err(GeohashError::InvalidCharacter {
            index: 2,
            byte: b' '
        })
    );
    assert!(matches!(
        Geohash::parse("gc💬"),
        Err(GeohashError::InvalidCharacter { index: 2, .. })
    ));
}

#[test]
fn rejects_invalid_precision_and_coordinates() {
    assert_eq!(
        Geohash::parse(""),
        Err(GeohashError::InvalidPrecision { precision: 0 })
    );
    assert_eq!(
        Geohash::parse("0".repeat(MAX_PRECISION + 1).as_str()),
        Err(GeohashError::InvalidPrecision {
            precision: MAX_PRECISION + 1
        })
    );
    assert!(matches!(
        encode(f64::NAN, 0.0, 5),
        Err(GeohashError::NonFiniteCoordinate)
    ));
    assert!(matches!(
        encode(90.1, 0.0, 5),
        Err(GeohashError::LatitudeOutOfRange { .. })
    ));
    assert!(matches!(
        encode(0.0, -180.1, 5),
        Err(GeohashError::LongitudeOutOfRange { .. })
    ));
}

#[test]
fn deterministic_coordinate_property_sweep() {
    let mut state = 0x4f4d_4143_4841_5401_u64;
    for index in 0..20_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let latitude = (state as f64 / u64::MAX as f64).mul_add(180.0, -90.0);
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let longitude = (state as f64 / u64::MAX as f64).mul_add(360.0, -180.0);
        let precision = index % MAX_PRECISION + 1;

        let encoded = encode(latitude, longitude, precision).unwrap();
        let bounds = encoded.bounds();
        assert!(bounds.contains(Coordinate {
            latitude,
            longitude
        }));
        assert_eq!(
            encode(
                encoded.center().latitude,
                encoded.center().longitude,
                precision
            )
            .unwrap(),
            encoded
        );
    }
}

#[test]
fn arbitrary_bytes_never_panic_or_bypass_validation() {
    for byte in u8::MIN..=u8::MAX {
        let input = String::from_utf8_lossy(&[byte; 12]).into_owned();
        if let Ok(parsed) = Geohash::parse(&input) {
            assert_eq!(parsed.as_str().len(), 12);
            assert!(
                parsed
                    .as_str()
                    .bytes()
                    .all(|candidate| b"0123456789bcdefghjkmnpqrstuvwxyz".contains(&candidate))
            );
        }
    }
}
