//! Event enrichment and ancestry reconstruction for pipeline telemetry.
//!
//! Per SDD §4.1.2 and FR-P02/FR-P03, the pipeline turns raw `SyscallEvent`
//! values into `EnrichedEvent`s by reading `/proc` metadata and reconstructing
//! a parent-first ancestry chain. The ancestry walk is iterative rather than
//! recursive so adversarial 10,000-level process trees cannot overflow the
//! stack, and the cache validates each PID against `/proc/<pid>/stat`
//! `starttime` so a wrapped/reused numeric PID never inherits a stale chain.

use crate::{ProcReadError, ProcReader};
use mini_edr_common::{EnrichedEvent, ProcessInfo, SyscallEvent, SyscallType};
use std::collections::HashMap;

const DEFAULT_MAX_ANCESTRY_DEPTH: usize = 1_024;

/// Enriches raw sensor events with `/proc` metadata and process ancestry.
#[derive(Debug)]
pub struct EventEnricher {
    proc_reader: ProcReader,
    max_ancestry_depth: usize,
    ancestry_cache: HashMap<u32, CachedAncestryEntry>,
}

impl EventEnricher {
    /// Default ancestry depth cap used to bound untrusted process trees.
    pub const DEFAULT_MAX_ANCESTRY_DEPTH: usize = DEFAULT_MAX_ANCESTRY_DEPTH;

    /// Construct an enricher with the documented default ancestry depth cap.
    #[must_use]
    pub fn new(proc_reader: ProcReader) -> Self {
        Self::with_max_ancestry_depth(proc_reader, Self::DEFAULT_MAX_ANCESTRY_DEPTH)
    }

    /// Construct an enricher with an explicit ancestry depth cap.
    ///
    /// A zero depth would make every event vacuously truncated, so the
    /// implementation clamps it to one entry instead. That keeps the API
    /// defensive while preserving the "observed process must still be present"
    /// invariant.
    #[must_use]
    pub fn with_max_ancestry_depth(proc_reader: ProcReader, max_ancestry_depth: usize) -> Self {
        Self {
            proc_reader,
            max_ancestry_depth: max_ancestry_depth.max(1),
            ancestry_cache: HashMap::new(),
        }
    }

    /// Enrich one raw syscall event with `/proc` metadata and ancestry.
    ///
    /// # Errors
    ///
    /// This method intentionally does not surface `/proc` races as a hard
    /// error. Per FR-P02 and NFR-R02, disappearing processes are a normal
    /// operating condition, so the enricher logs a warning and returns a
    /// structurally-valid `EnrichedEvent` with empty fallback metadata.
    #[must_use]
    pub fn enrich_event(&mut self, event: SyscallEvent) -> EnrichedEvent {
        self.invalidate_clone_related_cache(&event);

        let cgroup = match self.proc_reader.read_cgroup(event.pid) {
            Ok(cgroup) => cgroup,
            Err(error) => {
                tracing::warn!(
                    event = "enrichment_partial",
                    pid = event.pid,
                    field = "cgroup",
                    error = %error,
                    "procfs metadata disappeared while enriching an event"
                );
                String::new()
            }
        };

        let (process_name, binary_path, uid, ancestry_chain, ancestry_truncated) =
            match self.read_process_snapshot(event.pid) {
                Ok(leaf_snapshot) => {
                    let (ancestry_chain, ancestry_truncated) =
                        self.resolve_ancestry_chain(leaf_snapshot.clone());
                    (
                        leaf_snapshot.info.process_name,
                        leaf_snapshot.info.binary_path,
                        leaf_snapshot.uid,
                        ancestry_chain,
                        ancestry_truncated,
                    )
                }
                Err(error) => {
                    self.ancestry_cache.remove(&event.pid);
                    tracing::warn!(
                        event = "enrichment_partial",
                        pid = event.pid,
                        field = "identity",
                        error = %error,
                        "procfs identity disappeared while enriching an event"
                    );
                    (String::new(), String::new(), 0, Vec::new(), false)
                }
            };

        EnrichedEvent {
            event,
            process_name,
            binary_path,
            cgroup,
            uid,
            ancestry_chain,
            ancestry_truncated,
            repeat_count: 1,
        }
    }

    fn invalidate_clone_related_cache(&mut self, event: &SyscallEvent) {
        if event.syscall_type != SyscallType::Clone {
            return;
        }

        // Clone events are the earliest userspace signal that the process tree
        // may have changed. Dropping both the observed parent PID and the
        // returned child PID keeps later ancestry reads conservative, and the
        // `/proc/<pid>/stat` start-time fingerprint below prevents PID reuse
        // from ever reviving an old chain after numeric wraparound.
        self.ancestry_cache.remove(&event.pid);
        if let Some(child_pid) = event.child_pid.filter(|child_pid| *child_pid > 0) {
            self.ancestry_cache.remove(&child_pid);
        }
    }

    fn resolve_ancestry_chain(
        &mut self,
        leaf_snapshot: ProcessSnapshot,
    ) -> (Vec<ProcessInfo>, bool) {
        let mut snapshots_leaf_first = Vec::new();
        let mut current_pid = leaf_snapshot.pid;
        let mut next_snapshot = Some(leaf_snapshot);
        let mut ancestry_truncated = false;

        loop {
            let snapshot = match next_snapshot.take() {
                Some(snapshot) => snapshot,
                None => match self.read_process_snapshot(current_pid) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        self.ancestry_cache.remove(&current_pid);
                        tracing::warn!(
                            event = "enrichment_partial",
                            pid = current_pid,
                            field = "ancestor",
                            error = %error,
                            "ancestor disappeared while reconstructing ancestry"
                        );
                        break;
                    }
                },
            };

            if let Some(cached_entry) = self.ancestry_cache.get(&current_pid).cloned() {
                if cached_entry.fingerprint == snapshot.fingerprint {
                    let mut chain = cached_entry.chain;
                    chain.extend(
                        snapshots_leaf_first
                            .iter()
                            .rev()
                            .map(|snapshot: &ProcessSnapshot| snapshot.info.clone()),
                    );
                    ancestry_truncated |= cached_entry.truncated
                        || trim_chain_to_depth(&mut chain, self.max_ancestry_depth);
                    self.cache_visited_suffix(&snapshots_leaf_first, &chain, ancestry_truncated);
                    return (chain, ancestry_truncated);
                }

                self.ancestry_cache.remove(&current_pid);
            }

            let reached_root_sentinel = snapshot.pid == 1 || snapshot.parent_pid == 0;
            let next_parent_pid = snapshot.parent_pid;
            snapshots_leaf_first.push(snapshot);

            if snapshots_leaf_first.len() == self.max_ancestry_depth {
                ancestry_truncated = !reached_root_sentinel && next_parent_pid > 0;
                break;
            }

            if reached_root_sentinel {
                break;
            }

            current_pid = next_parent_pid;
        }

        let mut chain: Vec<ProcessInfo> = snapshots_leaf_first
            .iter()
            .rev()
            .map(|snapshot| snapshot.info.clone())
            .collect();
        ancestry_truncated |= trim_chain_to_depth(&mut chain, self.max_ancestry_depth);
        self.cache_visited_suffix(&snapshots_leaf_first, &chain, ancestry_truncated);
        (chain, ancestry_truncated)
    }

    fn cache_visited_suffix(
        &mut self,
        snapshots_leaf_first: &[ProcessSnapshot],
        chain: &[ProcessInfo],
        ancestry_truncated: bool,
    ) {
        if snapshots_leaf_first.is_empty() || chain.is_empty() {
            return;
        }

        let snapshots_parent_first: Vec<_> = snapshots_leaf_first.iter().rev().collect();
        let prefix_start = chain.len().saturating_sub(snapshots_parent_first.len());

        for (offset, snapshot) in snapshots_parent_first.into_iter().enumerate() {
            let prefix_end = prefix_start + offset;
            let cached_chain = chain[..=prefix_end].to_vec();
            self.ancestry_cache.insert(
                snapshot.pid,
                CachedAncestryEntry {
                    fingerprint: snapshot.fingerprint,
                    chain: cached_chain,
                    truncated: ancestry_truncated,
                },
            );
        }
    }

    fn read_process_snapshot(&self, pid: u32) -> Result<ProcessSnapshot, ProcReadError> {
        let status = self.proc_reader.read_status(pid)?;
        let stat = self.proc_reader.read_stat(pid)?;
        let executable = self.proc_reader.read_exe(pid)?;

        // We prefer `stat.ppid` because it is read alongside `starttime`, which
        // forms the PID-reuse fingerprint. Falling back to `status.ppid` for
        // non-root processes with a zero `stat.ppid` keeps the chain resilient
        // against rare cross-file races where one procfs file goes stale first.
        let parent_pid = if stat.ppid == 0 && pid != 1 {
            status.ppid
        } else {
            stat.ppid
        };

        Ok(ProcessSnapshot {
            pid,
            info: ProcessInfo {
                pid,
                process_name: status.name,
                binary_path: executable.display().to_string(),
            },
            uid: status.uid,
            parent_pid,
            fingerprint: ProcessFingerprint {
                parent_pid,
                start_time_ticks: stat.start_time_ticks,
            },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedAncestryEntry {
    fingerprint: ProcessFingerprint,
    chain: Vec<ProcessInfo>,
    truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessFingerprint {
    parent_pid: u32,
    start_time_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessSnapshot {
    pid: u32,
    info: ProcessInfo,
    uid: u32,
    parent_pid: u32,
    fingerprint: ProcessFingerprint,
}

fn trim_chain_to_depth(chain: &mut Vec<ProcessInfo>, max_ancestry_depth: usize) -> bool {
    if chain.len() <= max_ancestry_depth {
        return false;
    }

    let retained_suffix_start = chain.len() - max_ancestry_depth;
    chain.drain(..retained_suffix_start);
    true
}
