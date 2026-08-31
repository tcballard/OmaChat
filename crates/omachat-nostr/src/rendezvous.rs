//! Signed bridge rendezvous events using `r` and optional mesh `m` tags.

use crate::{
    event::{EventError, EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    geochat::{CHAT_KIND, PRESENCE_KIND},
};
use omachat_proto::geohash::Geohash;
use std::{error::Error, fmt};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RendezvousEvent {
    pub event_id: String,
    pub sender_pubkey: String,
    pub created_at: u64,
    pub geohash: Geohash,
    pub mesh_id: Option<String>,
    pub content: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn create(
    secret_key: &[u8; 32],
    created_at: u64,
    geohash: &Geohash,
    mesh_id: Option<&str>,
    content: Option<&str>,
    signature_aux: &[u8; 32],
    limits: &EventLimits,
) -> Result<SignedEvent, RendezvousError> {
    let mut tags = vec![vec!["r".into(), geohash.as_str().into()]];
    if let Some(mesh_id) = mesh_id {
        validate_mesh_id(mesh_id)?;
        tags.push(vec!["m".into(), mesh_id.into()]);
    }
    let (kind, content) = match content {
        Some(content) if !content.is_empty() => (CHAT_KIND, content.to_owned()),
        Some(_) => return Err(RendezvousError::InvalidContent),
        None => (PRESENCE_KIND, String::new()),
    };
    Ok(UnsignedEvent::new(
        hex::encode(xonly_public_key(secret_key)?),
        created_at,
        kind,
        tags,
        content,
        limits,
    )?
    .sign_with_aux(secret_key, signature_aux, limits)?)
}

pub fn parse(
    event: &SignedEvent,
    now: u64,
    limits: &EventLimits,
) -> Result<RendezvousEvent, RendezvousError> {
    event.verify(now, limits)?;
    if !matches!(event.kind, CHAT_KIND | PRESENCE_KIND)
        || event.tags.is_empty()
        || event.tags.len() > 2
    {
        return Err(RendezvousError::InvalidKind);
    }
    let mut rendezvous = None;
    let mut mesh_id = None;
    for tag in &event.tags {
        match tag.first().map(String::as_str) {
            Some("r") if tag.len() == 2 && rendezvous.is_none() => {
                rendezvous =
                    Some(Geohash::parse(&tag[1]).map_err(|_| RendezvousError::InvalidGeohash)?)
            }
            Some("m") if tag.len() == 2 && mesh_id.is_none() => {
                validate_mesh_id(&tag[1])?;
                mesh_id = Some(tag[1].clone());
            }
            _ => return Err(RendezvousError::InvalidTag),
        }
    }
    let content = match event.kind {
        CHAT_KIND if !event.content.is_empty() => Some(event.content.clone()),
        PRESENCE_KIND if event.content.is_empty() => None,
        _ => return Err(RendezvousError::InvalidContent),
    };
    Ok(RendezvousEvent {
        event_id: event.id.clone(),
        sender_pubkey: event.pubkey.clone(),
        created_at: event.created_at,
        geohash: rendezvous.ok_or(RendezvousError::InvalidTag)?,
        mesh_id,
        content,
    })
}

fn validate_mesh_id(value: &str) -> Result<(), RendezvousError> {
    if value.is_empty() || value.len() > 64 || value.chars().any(char::is_control) {
        Err(RendezvousError::InvalidMeshId)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum RendezvousError {
    Event(EventError),
    InvalidKind,
    InvalidTag,
    InvalidGeohash,
    InvalidMeshId,
    InvalidContent,
}
impl From<EventError> for RendezvousError {
    fn from(value: EventError) -> Self {
        Self::Event(value)
    }
}
impl fmt::Display for RendezvousError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid rendezvous event: {self:?}")
    }
}
impl Error for RendezvousError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(e) => Some(e),
            _ => None,
        }
    }
}
