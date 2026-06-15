//! feir `decision-core` — the single source of truth for the integrity pipeline:
//! canonicalize → commit → hash → sign → DAG-link → checkpoint → verify.
//!
//! One crate, three build targets: rlib (CLI + tests), cdylib/staticlib (cgo FFI), and WASM
//! (`--features wasm`). The golden vectors in `/spec/golden-vectors` are the cross-target
//! byte-for-byte contract (threat #10).

pub mod anchor;
pub mod authority;
pub mod b64;
pub mod canon;
pub mod checkpoint;
pub mod commit;
pub mod dag;
pub mod ffi;
pub mod hashx;
pub mod record;
#[cfg(feature = "rfc3161")]
pub mod rfc3161;
pub mod sign;
pub mod verify;

pub use canon::{CanonError, CanonValue};
pub use commit::{commit, verify_commitment, FieldDomain};
pub use record::{compute_content_hash, seal, verify_content_hash, verify_sealed, RecordError};
pub use sign::{signing_key_from_seed, SigError};

/// Crate version of the canonical profile this build implements.
pub const CANON_VERSION: &str = "rcp-1";
pub const SCHEMA_VERSION: &str = "2";
