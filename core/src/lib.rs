//! feir `decision-core` — the single source of truth for the integrity pipeline:
//! canonicalize → commit → hash → sign → DAG-link → checkpoint → verify.
//!
//! One crate, three build targets: rlib (CLI + tests), cdylib/staticlib (cgo FFI), and WASM
//! (`--features wasm`). The golden vectors in `/spec/golden-vectors` are the cross-target
//! byte-for-byte contract (threat #10).

pub mod canon;
pub mod hashx;
pub mod record;

pub use canon::{CanonError, CanonValue};
pub use record::{compute_content_hash, verify_content_hash, RecordError};

/// Crate version of the canonical profile this build implements.
pub const CANON_VERSION: &str = "rcp-1";
pub const SCHEMA_VERSION: &str = "2";
