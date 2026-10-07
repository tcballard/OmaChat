use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{error::Error, fmt, str::FromStr};
const MIN_HANDLE_BYTES: usize = 3;
const MAX_HANDLE_BYTES: usize = 32;
const MAX_DISPLAY_NAME_CHARS: usize = 80;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
/// A server-scoped account handle in canonical form, without the display
/// `@` prefix.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GlobalHandle(String);

impl GlobalHandle {
    pub fn parse(value: &str) -> Result<Self, AccountError> {
        let canonical = value.strip_prefix('@').unwrap_or(value);
        let bytes = canonical.as_bytes();
        if !(MIN_HANDLE_BYTES..=MAX_HANDLE_BYTES).contains(&bytes.len())
            || !bytes[0].is_ascii_lowercase()
            || !bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            return Err(AccountError::InvalidHandle);
        }
        Ok(Self(canonical.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GlobalHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for GlobalHandle {
    type Err = AccountError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for GlobalHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GlobalHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

/// A human-facing account name with explicit character and UTF-8 bounds.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayName(String);

impl DisplayName {
    pub fn parse(value: &str) -> Result<Self, AccountError> {
        let characters = value.chars().count();
        if characters == 0
            || characters > MAX_DISPLAY_NAME_CHARS
            || value.len() > MAX_DISPLAY_NAME_BYTES
            || value.trim() != value
            || value
                .chars()
                .any(|character| character.is_control() || is_unsafe_display_format(character))
        {
            return Err(AccountError::InvalidDisplayName);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for DisplayName {
    type Err = AccountError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for DisplayName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DisplayName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

fn is_unsafe_display_format(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

#[derive(Debug)]
pub enum AccountError {
    InvalidHandle,
    InvalidDisplayName,
}
impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidHandle => "invalid handle",
            Self::InvalidDisplayName => "invalid display name",
        })
    }
}
impl Error for AccountError {}
