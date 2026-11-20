use serde::{Deserialize, Serialize};

/// Check accounts location in signup queue.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CheckSignupQueueOutput {
    pub activated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_in_queue: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_time_ms: Option<i64>,
}

/// Whether a handle is available on this PDS.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CheckHandleAvailabilityOutput {
    /// Echo of the input handle.
    pub handle: String,
    pub result: CheckHandleAvailabilityResult,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "$type")]
pub enum CheckHandleAvailabilityResult {
    #[serde(rename = "com.atproto.temp.checkHandleAvailability#resultAvailable")]
    Available,
    #[serde(rename = "com.atproto.temp.checkHandleAvailability#resultUnavailable")]
    Unavailable {
        /// Suggested handles that are available.
        suggestions: Vec<HandleSuggestion>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HandleSuggestion {
    pub handle: String,
    /// Method used to build this suggestion. Opaque to clients.
    pub method: String,
}
