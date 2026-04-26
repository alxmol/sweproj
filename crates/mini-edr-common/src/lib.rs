//! Shared Mini-EDR domain and configuration foundation.
//!
//! This crate is intentionally dependency-free at workspace bootstrap time. Per
//! SDD §8.2, all other crates are allowed to depend on `mini-edr-common`, while
//! `mini-edr-common` depends on no workspace crate. That invariant prevents
//! cycles and gives later features a stable home for shared schemas.

/// Version marker used by downstream skeleton crates to prove they link against
/// the shared foundation without introducing reverse dependencies.
pub const WORKSPACE_TOPOLOGY_VERSION: &str = "mini-edr-workspace-v1";

#[cfg(test)]
mod tests {
    use super::WORKSPACE_TOPOLOGY_VERSION;

    #[test]
    fn topology_version_names_the_bootstrap_contract() {
        // This smoke test gives `cargo nextest run --workspace` a real test to
        // execute during the bootstrap feature. Later feature work will replace
        // this with schema and validation tests, but keeping this tiny assertion
        // now proves that the common crate test harness is wired correctly.
        assert_eq!(WORKSPACE_TOPOLOGY_VERSION, "mini-edr-workspace-v1");
    }
}
