#![warn(missing_docs)]
//! `hist` library: secret detectors, history readers, scan and clean.
//!
//! The binary (`src/main.rs`) is a thin CLI wrapper; all logic lives here
//! so it can be unit-tested and reused.

pub mod clean;
pub mod cli;
pub mod finding;
pub mod history;
pub mod scan;

pub use cli::Cli;
pub use finding::Finding;
// Detectors live in the shared `secdetect` crate (also used by `snip`).
pub use secdetect::{DETECTORS, Detector, REDACTED, detect, redact};
