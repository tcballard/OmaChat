use std::error::Error;
use std::fmt;

use serde::Serialize;
use url::Url;

use crate::event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key};

pub const PROFILE_METADATA_KIND: u32 = 0;
pub const MAX_NOSTR_NAME_BYTES: usize = 32;
pub const MAX_DISPLAY_NAME_CHARS: usize = 80;
pub const MAX_ABOUT_BYTES: usize = 2_048;
pub const MAX_PICTURE_URL_BYTES: usize = 2_048;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NostrProfileDraft {
    /// A portable Nostr profile name. It is not a globally unique handle claim.
    pub nostr_name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
}

pub fn create_profile_metadata(
    secret_key: &[u8; 32],
    created_at: u64,
    profile: &NostrProfileDraft,
    event_limits: &EventLimits,
) -> Result<SignedEvent, ProfileMetadataError> {
    let mut auxiliary_randomness = [0; 32];
    getrandom::fill(&mut auxiliary_randomness).map_err(|_| ProfileMetadataError::Random)?;
    create_profile_metadata_with_aux(
        secret_key,
        created_at,
        profile,
        &auxiliary_randomness,
        event_limits,
    )
}

pub fn create_profile_metadata_with_aux(
    secret_key: &[u8; 32],
    created_at: u64,
    profile: &NostrProfileDraft,
    auxiliary_randomness: &[u8; 32],
    event_limits: &EventLimits,
) -> Result<SignedEvent, ProfileMetadataError> {
    validate_profile(profile)?;
    let content = serde_json::to_string(&ProfileContent {
        name: profile.nostr_name.as_deref(),
        display_name: profile.display_name.as_deref(),
        about: profile.about.as_deref(),
        picture: profile.picture.as_deref(),
    })
    .map_err(|_| ProfileMetadataError::Encoding)?;
    let public_key = xonly_public_key(secret_key)
        .map_err(|error| ProfileMetadataError::InvalidKey(error.to_string()))?;
    UnsignedEvent::new(
        hex::encode(public_key),
        created_at,
        PROFILE_METADATA_KIND,
        Vec::new(),
        content,
        event_limits,
    )
    .map_err(|error| ProfileMetadataError::InvalidEvent(error.to_string()))?
    .sign_with_aux(secret_key, auxiliary_randomness, event_limits)
    .map_err(|error| ProfileMetadataError::InvalidEvent(error.to_string()))
}

fn validate_profile(profile: &NostrProfileDraft) -> Result<(), ProfileMetadataError> {
    if let Some(name) = &profile.nostr_name
        && (name.is_empty()
            || name.len() > MAX_NOSTR_NAME_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(ProfileMetadataError::InvalidNostrName);
    }
    if let Some(display_name) = &profile.display_name
        && (display_name.is_empty()
            || display_name.trim() != display_name
            || display_name.chars().count() > MAX_DISPLAY_NAME_CHARS
            || display_name.chars().any(char::is_control))
    {
        return Err(ProfileMetadataError::InvalidDisplayName);
    }
    if let Some(about) = &profile.about
        && (about.len() > MAX_ABOUT_BYTES
            || about
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t')))
    {
        return Err(ProfileMetadataError::InvalidAbout);
    }
    if let Some(picture) = &profile.picture {
        if picture.len() > MAX_PICTURE_URL_BYTES {
            return Err(ProfileMetadataError::InvalidPicture);
        }
        let parsed = Url::parse(picture).map_err(|_| ProfileMetadataError::InvalidPicture)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ProfileMetadataError::InvalidPicture);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct ProfileContent<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    about: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileMetadataError {
    Random,
    Encoding,
    InvalidKey(String),
    InvalidEvent(String),
    InvalidNostrName,
    InvalidDisplayName,
    InvalidAbout,
    InvalidPicture,
}

impl fmt::Display for ProfileMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => formatter.write_str("secure randomness unavailable"),
            Self::Encoding => formatter.write_str("profile metadata encoding failed"),
            Self::InvalidKey(error) => write!(formatter, "invalid Nostr key: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid profile event: {error}"),
            Self::InvalidNostrName => formatter.write_str(
                "Nostr profile name must be 1-32 ASCII letters, digits, dots, dashes, or underscores",
            ),
            Self::InvalidDisplayName => formatter.write_str("invalid profile display name"),
            Self::InvalidAbout => formatter.write_str("invalid profile biography"),
            Self::InvalidPicture => {
                formatter.write_str("profile picture must be a bounded HTTPS URL")
            }
        }
    }
}

impl Error for ProfileMetadataError {}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn standard_profile_keeps_the_existing_nostr_key_as_author() {
        let secret = [61; 32];
        let public_key = xonly_public_key(&secret).expect("public key");
        let profile = NostrProfileDraft {
            nostr_name: Some("tom.local".into()),
            display_name: Some("Tom Ballard".into()),
            about: Some("Building OmaChat".into()),
            picture: Some("https://example.com/tom.png".into()),
        };
        let event = create_profile_metadata_with_aux(
            &secret,
            NOW,
            &profile,
            &[13; 32],
            &EventLimits::default(),
        )
        .expect("signed profile");
        event
            .verify(NOW, &EventLimits::default())
            .expect("valid event");
        assert_eq!(event.kind, PROFILE_METADATA_KIND);
        assert_eq!(event.pubkey, hex::encode(public_key));
        assert!(event.tags.is_empty());
        let content: serde_json::Value =
            serde_json::from_str(&event.content).expect("JSON profile");
        assert_eq!(content["name"], "tom.local");
        assert_eq!(content["display_name"], "Tom Ballard");
        assert!(content.get("handle").is_none());
        assert!(content.get("owner").is_none());
    }

    #[test]
    fn empty_profile_is_a_valid_signed_metadata_clear() {
        let event = create_profile_metadata_with_aux(
            &[62; 32],
            NOW,
            &NostrProfileDraft::default(),
            &[14; 32],
            &EventLimits::default(),
        )
        .expect("signed profile clear");
        assert_eq!(event.content, "{}");
        event
            .verify(NOW, &EventLimits::default())
            .expect("valid event");
    }

    #[test]
    fn ambiguous_names_and_unsafe_presentation_fields_fail_before_signing() {
        let secret = [63; 32];
        let limits = EventLimits::default();
        assert_eq!(
            create_profile_metadata_with_aux(
                &secret,
                NOW,
                &NostrProfileDraft {
                    nostr_name: Some("t\u{f8ff}m".into()),
                    ..NostrProfileDraft::default()
                },
                &[15; 32],
                &limits,
            ),
            Err(ProfileMetadataError::InvalidNostrName)
        );
        assert_eq!(
            create_profile_metadata_with_aux(
                &secret,
                NOW,
                &NostrProfileDraft {
                    display_name: Some(" Tom".into()),
                    ..NostrProfileDraft::default()
                },
                &[15; 32],
                &limits,
            ),
            Err(ProfileMetadataError::InvalidDisplayName)
        );
        assert_eq!(
            create_profile_metadata_with_aux(
                &secret,
                NOW,
                &NostrProfileDraft {
                    picture: Some("http://example.com/tom.png".into()),
                    ..NostrProfileDraft::default()
                },
                &[15; 32],
                &limits,
            ),
            Err(ProfileMetadataError::InvalidPicture)
        );
    }
}
