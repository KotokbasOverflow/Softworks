//! `hist` library: secret detectors, history readers, scan and clean.
//!
//! The binary (`src/main.rs`) is a thin CLI wrapper; all logic lives here
//! so it can be unit-tested and reused.

pub mod clean;
pub mod cli;
pub mod detectors;
pub mod finding;
pub mod history;
pub mod scan;

pub use cli::Cli;
pub use finding::Finding;
