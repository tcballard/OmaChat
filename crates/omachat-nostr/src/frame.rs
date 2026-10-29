//! Bounded NIP-01 client and relay frame codecs.

use crate::event::{EventError, EventLimits, SignedEvent};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{error::Error, fmt};

/// A client-to-relay NIP-01 message.
#[derive(Clone, Debug, PartialEq)]
pub enum ClientFrame {
    Event(SignedEvent),
    Request {
        subscription_id: String,
        filters: Vec<Value>,
    },
    Close {
        subscription_id: String,
    },
    Auth(SignedEvent),
}

impl ClientFrame {
    /// Encode one compact JSON relay frame after enforcing local limits.
    pub fn to_json(&self, limits: &FrameLimits) -> Result<Vec<u8>, FrameError> {
        let bytes = match self {
            Self::Event(event) => serde_json::to_vec(&("EVENT", event)),
            Self::Request {
                subscription_id,
                filters,
            } => {
                validate_subscription_id(subscription_id, limits)?;
                if filters.is_empty() || filters.len() > limits.max_filters {
                    return Err(FrameError::InvalidFilterCount {
                        count: filters.len(),
                        maximum: limits.max_filters,
                    });
                }
                for filter in filters {
                    if !filter.is_object() {
                        return Err(FrameError::FilterMustBeObject);
                    }
                }
                let mut frame = Vec::with_capacity(filters.len() + 2);
                frame.push(Value::String("REQ".into()));
                frame.push(Value::String(subscription_id.clone()));
                frame.extend(filters.iter().cloned());
                serde_json::to_vec(&frame)
            }
            Self::Close { subscription_id } => {
                validate_subscription_id(subscription_id, limits)?;
                serde_json::to_vec(&("CLOSE", subscription_id))
            }
            Self::Auth(event) => serde_json::to_vec(&("AUTH", event)),
        }
        .map_err(FrameError::Json)?;
        validate_frame_size(bytes.len(), limits)?;
        Ok(bytes)
    }
}

/// A relay-to-client NIP-01/NIP-42 message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayFrame {
    Event {
        subscription_id: String,
        event: SignedEvent,
    },
    EndOfStoredEvents {
        subscription_id: String,
    },
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    Closed {
        subscription_id: String,
        message: String,
    },
    Notice(String),
    AuthChallenge(String),
}

impl RelayFrame {
    /// Decode one complete relay frame and authenticate any nested event.
    pub fn from_json(
        bytes: &[u8],
        now: u64,
        event_limits: &EventLimits,
        frame_limits: &FrameLimits,
    ) -> Result<Self, FrameError> {
        validate_frame_size(bytes.len(), frame_limits)?;
        let frame: WireRelayFrame = serde_json::from_slice(bytes).map_err(FrameError::Json)?;
        match frame {
            WireRelayFrame::Event {
                subscription_id,
                event,
            } => {
                validate_subscription_id(&subscription_id, frame_limits)?;
                event.verify(now, event_limits).map_err(FrameError::Event)?;
                Ok(Self::Event {
                    subscription_id,
                    event,
                })
            }
            WireRelayFrame::EndOfStoredEvents { subscription_id } => {
                validate_subscription_id(&subscription_id, frame_limits)?;
                Ok(Self::EndOfStoredEvents { subscription_id })
            }
            WireRelayFrame::Ok {
                event_id,
                accepted,
                message,
            } => {
                validate_hex_id(&event_id)?;
                validate_message(&message, frame_limits)?;
                Ok(Self::Ok {
                    event_id,
                    accepted,
                    message,
                })
            }
            WireRelayFrame::Closed {
                subscription_id,
                message,
            } => {
                validate_subscription_id(&subscription_id, frame_limits)?;
                validate_message(&message, frame_limits)?;
                Ok(Self::Closed {
                    subscription_id,
                    message,
                })
            }
            WireRelayFrame::Notice(message) => {
                validate_message(&message, frame_limits)?;
                Ok(Self::Notice(message))
            }
            WireRelayFrame::AuthChallenge(challenge) => {
                validate_message(&challenge, frame_limits)?;
                Ok(Self::AuthChallenge(challenge))
            }
        }
    }
}

/// Resource limits applied before relay-controlled allocation is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameLimits {
    pub max_frame_bytes: usize,
    pub max_subscription_id_bytes: usize,
    pub max_message_bytes: usize,
    pub max_filters: usize,
}

impl Default for FrameLimits {
    fn default() -> Self {
        // The pinned Swift WebSocket boundary is 512 KiB; nested events are
        // independently capped at 256 KiB by EventLimits.
        Self {
            max_frame_bytes: 512 * 1024,
            max_subscription_id_bytes: 64,
            max_message_bytes: 4 * 1024,
            max_filters: 16,
        }
    }
}

#[derive(Debug)]
pub enum FrameError {
    Json(serde_json::Error),
    Event(EventError),
    FrameTooLarge { bytes: usize, maximum: usize },
    InvalidSubscriptionId,
    InvalidEventId,
    MessageTooLarge { bytes: usize, maximum: usize },
    InvalidFilterCount { count: usize, maximum: usize },
    FilterMustBeObject,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid relay frame JSON: {error}"),
            Self::Event(error) => write!(formatter, "invalid relay event: {error}"),
            Self::FrameTooLarge { bytes, maximum } => {
                write!(
                    formatter,
                    "relay frame is {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidSubscriptionId => formatter.write_str("invalid subscription ID"),
            Self::InvalidEventId => formatter.write_str("invalid event ID"),
            Self::MessageTooLarge { bytes, maximum } => {
                write!(
                    formatter,
                    "relay message is {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidFilterCount { count, maximum } => write!(
                formatter,
                "subscription has {count} filters; expected 1..={maximum}"
            ),
            Self::FilterMustBeObject => {
                formatter.write_str("subscription filter must be an object")
            }
        }
    }
}

impl Error for FrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Event(error) => Some(error),
            _ => None,
        }
    }
}

enum WireRelayFrame {
    Event {
        subscription_id: String,
        event: SignedEvent,
    },
    EndOfStoredEvents {
        subscription_id: String,
    },
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    Closed {
        subscription_id: String,
        message: String,
    },
    Notice(String),
    AuthChallenge(String),
}

impl<'de> Deserialize<'de> for WireRelayFrame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(WireRelayFrameVisitor)
    }
}

struct WireRelayFrameVisitor;

impl<'de> Visitor<'de> for WireRelayFrameVisitor {
    type Value = WireRelayFrame;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a supported NIP-01 relay message array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let kind: String = required(&mut sequence, "message type")?;
        let frame = match kind.as_str() {
            "EVENT" => WireRelayFrame::Event {
                subscription_id: required(&mut sequence, "subscription ID")?,
                event: required(&mut sequence, "event")?,
            },
            "EOSE" => WireRelayFrame::EndOfStoredEvents {
                subscription_id: required(&mut sequence, "subscription ID")?,
            },
            "OK" => WireRelayFrame::Ok {
                event_id: required(&mut sequence, "event ID")?,
                accepted: required(&mut sequence, "acceptance flag")?,
                message: required(&mut sequence, "message")?,
            },
            "CLOSED" => WireRelayFrame::Closed {
                subscription_id: required(&mut sequence, "subscription ID")?,
                message: required(&mut sequence, "message")?,
            },
            "NOTICE" => WireRelayFrame::Notice(required(&mut sequence, "message")?),
            "AUTH" => WireRelayFrame::AuthChallenge(required(&mut sequence, "challenge")?),
            _ => return Err(A::Error::custom("unsupported relay message type")),
        };
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("relay message has trailing fields"));
        }
        Ok(frame)
    }
}

fn required<'de, A, T>(sequence: &mut A, name: &str) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: Deserialize<'de>,
{
    sequence
        .next_element()?
        .ok_or_else(|| A::Error::custom(format_args!("relay message is missing {name}")))
}

fn validate_frame_size(bytes: usize, limits: &FrameLimits) -> Result<(), FrameError> {
    if bytes > limits.max_frame_bytes {
        Err(FrameError::FrameTooLarge {
            bytes,
            maximum: limits.max_frame_bytes,
        })
    } else {
        Ok(())
    }
}

fn validate_subscription_id(value: &str, limits: &FrameLimits) -> Result<(), FrameError> {
    if value.is_empty()
        || value.len() > limits.max_subscription_id_bytes
        || value.chars().any(char::is_control)
    {
        Err(FrameError::InvalidSubscriptionId)
    } else {
        Ok(())
    }
}

fn validate_message(value: &str, limits: &FrameLimits) -> Result<(), FrameError> {
    if value.len() > limits.max_message_bytes {
        Err(FrameError::MessageTooLarge {
            bytes: value.len(),
            maximum: limits.max_message_bytes,
        })
    } else {
        Ok(())
    }
}

fn validate_hex_id(value: &str) -> Result<(), FrameError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(FrameError::InvalidEventId)
    }
}
