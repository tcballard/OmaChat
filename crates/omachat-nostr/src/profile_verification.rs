use std::error::Error;
use std::fmt;

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::event::{EventLimits, SignedEvent};
use crate::profile_metadata::{
    MAX_ABOUT_BYTES, MAX_DISPLAY_NAME_CHARS, MAX_PICTURE_URL_BYTES, PROFILE_METADATA_KIND,
};

pub const MAX_EXTERNAL_NOSTR_NAME_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNostrProfile {
    public_key: [u8; 32],
    source_event_id: String,
    source_created_at: u64,
    nostr_name: Option<String>,
    name_classification: Option<ProfileNameClassification>,
    display_name: Option<String>,
    about: Option<String>,
    picture: Option<String>,
}

impl VerifiedNostrProfile {
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    pub fn source_created_at(&self) -> u64 {
        self.source_created_at
    }

    pub fn nostr_name(&self) -> Option<&str> {
        self.nostr_name.as_deref()
    }

    pub fn name_classification(&self) -> Option<ProfileNameClassification> {
        self.name_classification
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn about(&self) -> Option<&str> {
        self.about.as_deref()
    }

    pub fn picture(&self) -> Option<&str> {
        self.picture.as_deref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileNameClassification {
    HandleSyntaxCandidate,
    PresentationOnly,
}

pub fn verify_profile_metadata(
    event: &SignedEvent,
    expected_public_key: &[u8; 32],
    now: u64,
    event_limits: &EventLimits,
) -> Result<VerifiedNostrProfile, ProfileVerificationError> {
    event
        .verify(now, event_limits)
        .map_err(|error| ProfileVerificationError::InvalidEvent(error.to_string()))?;
    if event.kind != PROFILE_METADATA_KIND {
        return Err(ProfileVerificationError::WrongKind);
    }
    if event.pubkey != hex::encode(expected_public_key) {
        return Err(ProfileVerificationError::AuthorMismatch);
    }
    if !event.tags.is_empty() {
        return Err(ProfileVerificationError::UnexpectedTags);
    }

    let raw: RawProfile = serde_json::from_str(&event.content)
        .map_err(|error| ProfileVerificationError::InvalidContent(error.to_string()))?;
    let name_classification = raw.nostr_name.as_ref().map(|name| {
        if name.len() <= 32
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            ProfileNameClassification::HandleSyntaxCandidate
        } else {
            ProfileNameClassification::PresentationOnly
        }
    });
    validate_known_fields(&raw)?;

    Ok(VerifiedNostrProfile {
        public_key: *expected_public_key,
        source_event_id: event.id.clone(),
        source_created_at: event.created_at,
        nostr_name: raw.nostr_name,
        name_classification,
        display_name: raw.display_name,
        about: raw.about,
        picture: raw.picture,
    })
}

fn validate_known_fields(raw: &RawProfile) -> Result<(), ProfileVerificationError> {
    if let Some(name) = &raw.nostr_name
        && (name.is_empty()
            || name.len() > MAX_EXTERNAL_NOSTR_NAME_BYTES
            || name.chars().any(char::is_control))
    {
        return Err(ProfileVerificationError::InvalidNostrName);
    }
    if let Some(display_name) = &raw.display_name
        && (display_name.is_empty()
            || display_name.trim() != display_name
            || display_name.chars().count() > MAX_DISPLAY_NAME_CHARS
            || display_name.chars().any(char::is_control))
    {
        return Err(ProfileVerificationError::InvalidDisplayName);
    }
    if let Some(about) = &raw.about
        && (about.len() > MAX_ABOUT_BYTES
            || about
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t')))
    {
        return Err(ProfileVerificationError::InvalidAbout);
    }
    if let Some(picture) = &raw.picture {
        if picture.len() > MAX_PICTURE_URL_BYTES {
            return Err(ProfileVerificationError::InvalidPicture);
        }
        let parsed = Url::parse(picture).map_err(|_| ProfileVerificationError::InvalidPicture)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ProfileVerificationError::InvalidPicture);
        }
    }
    Ok(())
}

#[derive(Default)]
struct RawProfile {
    nostr_name: Option<String>,
    display_name: Option<String>,
    about: Option<String>,
    picture: Option<String>,
}

impl<'de> Deserialize<'de> for RawProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawProfileVisitor)
    }
}

struct RawProfileVisitor;

impl<'de> Visitor<'de> for RawProfileVisitor {
    type Value = RawProfile;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Nostr profile metadata object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut profile = RawProfile::default();
        let mut seen_name = false;
        let mut seen_display_name = false;
        let mut seen_about = false;
        let mut seen_picture = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "name" => {
                    reject_duplicate(&mut seen_name, "name")?;
                    profile.nostr_name = Some(map.next_value()?);
                }
                "display_name" => {
                    reject_duplicate(&mut seen_display_name, "display_name")?;
                    profile.display_name = Some(map.next_value()?);
                }
                "about" => {
                    reject_duplicate(&mut seen_about, "about")?;
                    profile.about = Some(map.next_value()?);
                }
                "picture" => {
                    reject_duplicate(&mut seen_picture, "picture")?;
                    profile.picture = Some(map.next_value()?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(profile)
    }
}

fn reject_duplicate<E>(seen: &mut bool, field: &'static str) -> Result<(), E>
where
    E: de::Error,
{
    if *seen {
        return Err(E::duplicate_field(field));
    }
    *seen = true;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileVerificationError {
    InvalidEvent(String),
    WrongKind,
    AuthorMismatch,
    UnexpectedTags,
    InvalidContent(String),
    InvalidNostrName,
    InvalidDisplayName,
    InvalidAbout,
    InvalidPicture,
}

impl fmt::Display for ProfileVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvent(error) => write!(formatter, "invalid profile event: {error}"),
            Self::WrongKind => formatter.write_str("profile metadata requires kind 0"),
            Self::AuthorMismatch => {
                formatter.write_str("profile author does not match participant")
            }
            Self::UnexpectedTags => formatter.write_str("profile metadata must not contain tags"),
            Self::InvalidContent(error) => write!(formatter, "invalid profile JSON: {error}"),
            Self::InvalidNostrName => formatter.write_str("invalid Nostr profile name"),
            Self::InvalidDisplayName => formatter.write_str("invalid profile display name"),
            Self::InvalidAbout => formatter.write_str("invalid profile biography"),
            Self::InvalidPicture => formatter.write_str("invalid profile picture URL"),
        }
    }
}

impl Error for ProfileVerificationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{UnsignedEvent, xonly_public_key};

    const NOW: u64 = 1_800_000_000;

    fn signed_profile(secret_key: &[u8; 32], content: &str) -> SignedEvent {
        UnsignedEvent::new(
            hex::encode(xonly_public_key(secret_key).expect("public key")),
            NOW,
            PROFILE_METADATA_KIND,
            Vec::new(),
            content.to_owned(),
            &EventLimits::default(),
        )
        .expect("profile event")
        .sign_with_aux(secret_key, &[16; 32], &EventLimits::default())
        .expect("signed profile")
    }

    #[test]
    fn external_profiles_keep_their_key_and_untrusted_extensions_stay_unexposed() {
        let secret = [71; 32];
        let public_key = xonly_public_key(&secret).expect("public key");
        let event = signed_profile(
            &secret,
            r#"{"name":"tøm","display_name":"Tom","nip05":"tom@example.com","bot":true}"#,
        );
        let profile = verify_profile_metadata(&event, &public_key, NOW, &EventLimits::default())
            .expect("verified external profile");
        assert_eq!(profile.public_key(), &public_key);
        assert_eq!(profile.source_event_id(), event.id);
        assert_eq!(profile.nostr_name(), Some("tøm"));
        assert_eq!(
            profile.name_classification(),
            Some(ProfileNameClassification::PresentationOnly)
        );
        assert_eq!(profile.display_name(), Some("Tom"));
    }

    #[test]
    fn handle_safe_syntax_is_classification_not_uniqueness_evidence() {
        let secret = [72; 32];
        let public_key = xonly_public_key(&secret).expect("public key");
        let event = signed_profile(&secret, r#"{"name":"codex_tom"}"#);
        let profile = verify_profile_metadata(&event, &public_key, NOW, &EventLimits::default())
            .expect("verified profile");
        assert_eq!(
            profile.name_classification(),
            Some(ProfileNameClassification::HandleSyntaxCandidate)
        );
    }

    #[test]
    fn relay_source_cannot_override_signature_author_or_strict_known_fields() {
        let secret = [73; 32];
        let public_key = xonly_public_key(&secret).expect("public key");
        let attacker = [74; 32];
        assert_eq!(
            verify_profile_metadata(
                &signed_profile(&attacker, r#"{"name":"tom"}"#),
                &public_key,
                NOW,
                &EventLimits::default(),
            ),
            Err(ProfileVerificationError::AuthorMismatch)
        );

        let mut tampered = signed_profile(&secret, r#"{"name":"tom"}"#);
        tampered.content = r#"{"name":"attacker"}"#.into();
        assert!(matches!(
            verify_profile_metadata(&tampered, &public_key, NOW, &EventLimits::default()),
            Err(ProfileVerificationError::InvalidEvent(_))
        ));
        assert!(matches!(
            verify_profile_metadata(
                &signed_profile(&secret, r#"{"name":"tom","name":"attacker"}"#),
                &public_key,
                NOW,
                &EventLimits::default(),
            ),
            Err(ProfileVerificationError::InvalidContent(_))
        ));
        assert_eq!(
            verify_profile_metadata(
                &signed_profile(&secret, r#"{"picture":"http://example.com/me.png"}"#),
                &public_key,
                NOW,
                &EventLimits::default(),
            ),
            Err(ProfileVerificationError::InvalidPicture)
        );
    }
}
