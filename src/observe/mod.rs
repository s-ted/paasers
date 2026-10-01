//! Observability: trace context, flight recorder, error pages and body watching.
pub mod body_watch;
pub mod fallback;
pub mod recorder;
pub mod trace;

pub use recorder::{FlightRecorder, Incident, Query};
