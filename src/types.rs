use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

use anyhow::Result;
use bytes::Bytes;
use iroh::{EndpointAddr, EndpointId, PublicKey, SecretKey, Signature};
use iroh_gossip::TopicId;
use serde::{Deserialize, Serialize};

use crate::utils::time_now;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Invited {
        topic: TopicId,
        rnum: Vec<u8>,
        addr: EndpointAddr,
        alias: String,
        services: BTreeMap<String, u32>,
    },
    AboutMe {
        addr: EndpointAddr,
        alias: String,
        services: BTreeMap<String, u32>,
        invitor: EndpointId,
    },
    Introduce {
        invited: EndpointId,
    },
    SyncRequest {
        nodes: Vec<Node>,
    },
    SyncResponse {
        nodes: Vec<Node>,
    },
    Heartbeat,
    Left,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignedMessage {
    pub(crate) from: EndpointId,
    pub(crate) data: Bytes,
    signature: Signature,
    timestamp: u64,
}

impl SignedMessage {
    pub fn decode(bytes: Bytes) -> Result<Self> {
        Ok(postcard::from_bytes(bytes.as_ref())?)
    }

    pub fn verify_and_decode_message(&self) -> Result<(PublicKey, Message)> {
        let key: PublicKey = self.from;
        key.verify(&self.data, &self.signature)?;
        let message: Message = postcard::from_bytes(&self.data)?;
        Ok((key, message))
    }

    pub fn is_fresh(&self, now: u64) -> bool {
        self.timestamp < now + 10
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: Message) -> Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        let timestamp = time_now();
        let signed_message = Self {
            from,
            data,
            signature,
            timestamp,
        };
        let encoded = postcard::to_stdvec(&signed_message)?;
        Ok(encoded.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub node_id: EndpointId,
    pub invitor: EndpointId,
    pub addr: EndpointAddr,
    pub domain: String,
    pub services: BTreeMap<String, u32>,
    pub last_heartbeat: u64,
}

#[derive(Debug, Clone)]
pub struct Auth {
    pub introducer: EndpointId,
    pub introduced: bool,
    pub node: Option<Box<Node>>,
    pub timestamp: u64,
}

impl Hash for Node {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.node_id.hash(state);
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
    }
}

impl Eq for Node {}

impl Hash for Auth {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.introducer.hash(state);
    }
}

impl PartialEq for Auth {
    fn eq(&self, other: &Self) -> bool {
        self.introducer == other.introducer
    }
}

impl Eq for Auth {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_message_roundtrip_verifies() -> Result<()> {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let msg = Message::Heartbeat;
        let encoded = SignedMessage::sign_and_encode(&sk, msg.clone())?;
        let decoded = SignedMessage::decode(encoded)?;
        let (from, decoded_msg) = decoded.verify_and_decode_message()?;

        assert_eq!(from, pk);
        matches!(decoded_msg, Message::Heartbeat);
        assert!(decoded.is_fresh(time_now()));
        Ok(())
    }
}
