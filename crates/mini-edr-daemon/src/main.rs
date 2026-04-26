//! Mini-EDR daemon bootstrap binary.
//!
//! The daemon crate is the only workspace member that depends on every subsystem
//! crate. That design follows SDD §8.2: leaf crates remain independently
//! testable, and the binary will later own Tokio task wiring, signal handling,
//! and channel topology without forcing leaf crates to depend on one another.

// Binary entry points cannot be `const fn` because the operating system calls
// them at runtime; this explicit allow keeps the workspace-wide pedantic lint
// policy enabled without pretending the bootstrap daemon has const semantics.
#[allow(clippy::missing_const_for_fn)]
fn main() {
    // The first foundation feature verifies workspace shape only. Runtime
    // startup is implemented in later daemon/system-integration features.
}
