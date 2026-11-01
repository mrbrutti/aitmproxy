//! Identifier newtypes and aliases shared by every scanner v2 wire type (spec D2).
//!
//! `aitm-core` carries no serde, and this crate does not add it there. `FlowRef`
//! wraps a `FlowId` and gives it the one wire form the scanner contract uses: the
//! UUID string, exactly as `FlowId`'s `Display` renders it.

use std::fmt;
use std::str::FromStr;

use aitm_core::FlowId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A reference to a captured flow, on the wire as its UUID string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowRef(pub FlowId);

impl From<FlowId> for FlowRef {
    fn from(id: FlowId) -> Self {
        Self(id)
    }
}

impl fmt::Display for FlowRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for FlowRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for FlowRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        FlowId::from_str(&text)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// A site-map node identifier (`scan.sitemap`, spec D8.1).
pub type NodeId = String;

/// A scan job identifier, minted by the engine as `scan-<8 hex>` (spec D5).
pub type JobId = String;

/// An issue identifier, stable for the life of a job (spec D6).
pub type IssueId = String;

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn flow_ref_round_trips_uuid_string() {
        let id: aitm_core::FlowId = UUID.parse().expect("uuid parses");
        let flow_ref = FlowRef::from(id);

        let json = serde_json::to_string(&flow_ref).expect("serializes");
        assert_eq!(json, format!("\"{UUID}\""));

        let parsed: FlowRef = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(parsed, flow_ref);
        assert_eq!(parsed.to_string(), UUID);
    }
}
