//! Dynamic eBPF probe lifecycle management for the Mini-EDR sensor.
//!
//! SDD §4.1.1 names `SensorManager` as the userspace owner of the Aya `Ebpf`
//! object and `ProbeHandle` values as the API used to detach or reattach one
//! tracepoint at runtime. This module implements FR-S05 while preserving the
//! FR-S04 CO-RE/BTF contract: the manager loads the same BTF-enabled object
//! produced by `bpf-linker --btf` and never rebuilds per running kernel.

use crate::{
    bpf::{
        AUXILIARY_BPF_PROGRAMS, AuxiliaryBpfProgramSpec, BpfProgramSpec, BuildError,
        EVENT_RINGBUF_MAP, PPID_BY_TGID_MAP, build_ebpf_object, probe_program_specs,
    },
    kernel_metrics::{KernelCounterMaps, KernelCounterReadError, KernelCounterSnapshot},
    raw_event::RawSyscallEvent,
};
use aya::{
    Btf, Ebpf, EbpfError, EbpfLoader,
    maps::{HashMap as AyaHashMap, MapError, RingBuf},
    programs::{ProgramError, TracePoint, trace_point::TracePointLinkId},
};
use mini_edr_common::{Config, SyscallType};
use std::{
    collections::HashMap,
    fs, io, mem,
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
};
use tokio::sync::Mutex;

/// Public ordering used when attaching the four FR-S01 probes.
pub const DEFAULT_PROBE_TYPES: [SyscallType; 4] = [
    SyscallType::Execve,
    SyscallType::Openat,
    SyscallType::Connect,
    SyscallType::Clone,
];

/// Maximum raw events returned by one synchronous drain helper call.
///
/// Live hosts can produce unrelated `openat` noise while privileged tests are
/// polling. Bounding one drain pass prevents a lifecycle check from spinning
/// forever when the producer rate temporarily exceeds the test consumer rate.
const MAX_RAW_DRAIN_BATCH: usize = 4096;

/// Mini-EDR's current page-size assumption for ring-buffer sizing.
///
/// The product requirement is expressed in memory pages (`ring_buffer_size_pages`),
/// while Aya's `set_max_entries` API wants a ring-buffer byte size. Mini-EDR
/// currently targets `x86_64` and `aarch64` developer hosts where the base page
/// size is 4096 bytes; if the project later targets architectures with a
/// different base page size, both this conversion and the validation contract's
/// "4 pages = 16 KiB" assumption must be revisited together.
const RINGBUF_PAGE_SIZE_BYTES: u32 = 4096;
/// Maximum number of process-TGID → parent-process-TGID entries the support-map
/// design can retain.
///
/// The eBPF-side `PPID_BY_TGID` map matches Linux's default `pid_max`
/// (65,536). Because each entry carries only an 8-byte key/value payload, the
/// raw storage cost is about 512 KiB before the kernel's hash metadata, which
/// is an acceptable tradeoff for keeping one parent-process mapping per live
/// process. If future soak tests show pressure from temporary thread-clone
/// inserts, an `LruHashMap` remains an acceptable follow-up.
const PPID_INDEX_MAX_ENTRIES: usize = 65_536;

trait RingBufferMapSizer {
    fn set_max_entries(&mut self, map_name: &'static str, max_entries: u32);
}

impl RingBufferMapSizer for EbpfLoader<'_> {
    fn set_max_entries(&mut self, map_name: &'static str, max_entries: u32) {
        EbpfLoader::set_max_entries(self, map_name, max_entries);
    }
}

fn configure_events_ringbuf_on_loader(
    loader: &mut impl RingBufferMapSizer,
    ring_buffer_size_pages: u32,
) -> Result<u32, SensorManagerError> {
    let byte_size = ring_buffer_size_pages
        .checked_mul(RINGBUF_PAGE_SIZE_BYTES)
        .ok_or(SensorManagerError::RingBufferSizeOverflow {
            pages: ring_buffer_size_pages,
        })?;
    loader.set_max_entries(EVENT_RINGBUF_MAP, byte_size);
    Ok(byte_size)
}

/// Static metadata for one managed tracepoint probe.
///
/// The fields mirror `BpfProgramSpec` but use `SyscallType` so daemon/API code
/// can address probes using user-facing names such as `connect` rather than raw
/// eBPF symbol names. All values are `'static` because they describe compiled
/// object metadata, not mutable runtime state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeMetadata {
    /// User-facing syscall represented by this probe.
    pub syscall_type: SyscallType,
    /// Aya program symbol compiled into the eBPF object.
    pub program_name: &'static str,
    /// Kernel tracepoint category passed to `TracePoint::attach`.
    pub category: &'static str,
    /// Kernel tracepoint name passed to `TracePoint::attach`.
    pub tracepoint: &'static str,
    program_specs: &'static [BpfProgramSpec],
}

impl ProbeMetadata {
    const fn from_primary_spec(
        syscall_type: SyscallType,
        primary_spec: BpfProgramSpec,
        program_specs: &'static [BpfProgramSpec],
    ) -> Self {
        Self {
            syscall_type,
            program_name: primary_spec.program_name,
            category: primary_spec.category,
            tracepoint: primary_spec.tracepoint,
            program_specs,
        }
    }

    const fn program_specs(self) -> &'static [BpfProgramSpec] {
        self.program_specs
    }
}

/// Coarse lifecycle state exposed for health checks and tests.
///
/// The link ID itself is intentionally private because Aya link IDs must be
/// consumed exactly once by `TracePoint::detach`. Exposing only this enum keeps
/// the public API from accidentally double-detaching a kernel link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeLifecycleState {
    /// No live tracepoint link is held for this probe.
    Detached = 0,
    /// A tracepoint link is currently attached in the kernel.
    Attached = 1,
    /// The most recent attach or detach failed and operator attention is needed.
    Faulted = 2,
}

impl ProbeLifecycleState {
    const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Attached,
            2 => Self::Faulted,
            _ => Self::Detached,
        }
    }
}

/// Handle for one runtime tracepoint probe.
///
/// `ProbeHandle` is cloneable so `SensorManager::attach_probes` can return API
/// handles while the manager retains its own copies for bulk detach/reload. All
/// clones share the same link slot, so detaching through one handle immediately
/// updates the lifecycle state observed by the others.
#[derive(Clone)]
pub struct ProbeHandle {
    metadata: ProbeMetadata,
    bpf: Option<Arc<Mutex<Ebpf>>>,
    state: Arc<ProbeState>,
}

impl ProbeHandle {
    fn new(metadata: ProbeMetadata, bpf: Option<Arc<Mutex<Ebpf>>>) -> Self {
        Self {
            metadata,
            bpf,
            state: Arc::new(ProbeState::default()),
        }
    }

    /// Return the syscall managed by this handle.
    #[must_use]
    pub const fn syscall_type(&self) -> SyscallType {
        self.metadata.syscall_type
    }

    /// Return immutable tracepoint metadata for this handle.
    #[must_use]
    pub const fn metadata(&self) -> ProbeMetadata {
        self.metadata
    }

    /// Return the handle's current lifecycle state.
    #[must_use]
    pub fn lifecycle_state(&self) -> ProbeLifecycleState {
        ProbeLifecycleState::from_u8(self.state.lifecycle.load(Ordering::Acquire))
    }

    /// Return the number of successful attach transitions for this handle.
    #[must_use]
    pub fn attach_generation(&self) -> u64 {
        self.state.generation.load(Ordering::Acquire)
    }

    /// Attach this single probe if it is not already attached.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError` if the manager was constructed without a
    /// loaded BPF object, if the compiled program is missing or not a
    /// tracepoint, if the kernel verifier rejects the load, or if perf-event
    /// attachment fails.
    pub async fn attach(&self) -> Result<(), SensorManagerError> {
        let mut link_slot = self.state.links.lock().await;
        if !link_slot.is_empty() {
            self.state.store_lifecycle(ProbeLifecycleState::Attached);
            drop(link_slot);
            return Ok(());
        }

        let Some(bpf) = self.bpf.clone() else {
            self.state.store_lifecycle(ProbeLifecycleState::Faulted);
            drop(link_slot);
            return Err(SensorManagerError::ObjectNotLoaded);
        };

        // Synchronization invariant: per-probe operations always acquire this
        // handle's link-slot mutex before awaiting the shared Tokio Mutex that
        // wraps Aya's `Ebpf` object. The link-slot mutex prevents two callers
        // from attaching the same tracepoint twice, while the `Ebpf` mutex
        // serializes Aya's mutable program/map APIs across all four probes.
        // This ordering is mirrored by `detach`, which keeps reloads and
        // API-driven one-probe detach calls from deadlocking each other.
        let links = {
            let mut bpf_guard = bpf.lock().await;
            let mut attached_links = Vec::with_capacity(self.metadata.program_specs().len());
            for spec in self.metadata.program_specs() {
                let program = match tracepoint_program_mut_by_program_name(
                    &mut bpf_guard,
                    spec.program_name,
                    self.metadata.syscall_type,
                ) {
                    Ok(program) => program,
                    Err(error) => {
                        rollback_attached_program_links(
                            &mut bpf_guard,
                            self.metadata.syscall_type,
                            &mut attached_links,
                        );
                        self.state.store_lifecycle(ProbeLifecycleState::Faulted);
                        return Err(error);
                    }
                };

                // Aya keeps link IDs inside the program's internal link map. We
                // load once and treat `AlreadyLoaded` as success so a later
                // per-probe reattach does not require rebuilding/reloading the
                // CO-RE object.
                if let Err(error) = program.load()
                    && !matches!(error, ProgramError::AlreadyLoaded)
                {
                    rollback_attached_program_links(
                        &mut bpf_guard,
                        self.metadata.syscall_type,
                        &mut attached_links,
                    );
                    self.state.store_lifecycle(ProbeLifecycleState::Faulted);
                    return Err(SensorManagerError::Program {
                        syscall_type: self.metadata.syscall_type,
                        operation: "load",
                        source: error,
                    });
                }

                match program.attach(spec.category, spec.tracepoint) {
                    Ok(link_id) => attached_links.push(AttachedProgramLink {
                        program_name: spec.program_name,
                        link_id,
                    }),
                    Err(source) => {
                        rollback_attached_program_links(
                            &mut bpf_guard,
                            self.metadata.syscall_type,
                            &mut attached_links,
                        );
                        self.state.store_lifecycle(ProbeLifecycleState::Faulted);
                        return Err(SensorManagerError::Program {
                            syscall_type: self.metadata.syscall_type,
                            operation: "attach",
                            source,
                        });
                    }
                }
            }
            drop(bpf_guard);
            attached_links
        };
        *link_slot = links;
        drop(link_slot);
        self.state.generation.fetch_add(1, Ordering::AcqRel);
        self.state.store_lifecycle(ProbeLifecycleState::Attached);
        Ok(())
    }

    /// Detach this single probe without touching the other probe handles.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError` if the underlying BPF object is unavailable
    /// or Aya fails to detach the stored tracepoint link from the owning
    /// program. Calling `detach` on an already-detached handle is a no-op.
    pub async fn detach(&self) -> Result<(), SensorManagerError> {
        let mut link_slot = self.state.links.lock().await;
        if link_slot.is_empty() {
            self.state.store_lifecycle(ProbeLifecycleState::Detached);
            drop(link_slot);
            return Ok(());
        }
        let links = mem::take(&mut *link_slot);

        let Some(bpf) = self.bpf.clone() else {
            *link_slot = links;
            self.state.store_lifecycle(ProbeLifecycleState::Faulted);
            drop(link_slot);
            return Err(SensorManagerError::ObjectNotLoaded);
        };

        // Synchronization invariant: every attach/detach operation first locks
        // this probe's link slot, then locks the process-wide Tokio Mutex that
        // protects Aya's `Ebpf` object. Keeping one global order prevents a
        // connect-only detach from racing a bulk reload into deadlock, and the
        // per-probe slot means detaching `connect` never removes exec/open/clone
        // link IDs from their independent Aya programs.
        let detach_error = {
            let mut bpf_guard = bpf.lock().await;
            let mut first_error = None;
            for AttachedProgramLink {
                program_name,
                link_id,
            } in links
            {
                let detach_result: Result<(), SensorManagerError> =
                    tracepoint_program_mut_by_program_name(
                        &mut bpf_guard,
                        program_name,
                        self.metadata.syscall_type,
                    )
                    .and_then(|program: &mut TracePoint| {
                        program
                            .detach(link_id)
                            .map_err(|source| SensorManagerError::Program {
                                syscall_type: self.metadata.syscall_type,
                                operation: "detach",
                                source,
                            })
                    });
                if first_error.is_none() {
                    first_error = detach_result.err();
                }
            }
            drop(bpf_guard);
            first_error
        };
        drop(link_slot);
        detach_error.map_or_else(
            || {
                self.state.store_lifecycle(ProbeLifecycleState::Detached);
                Ok(())
            },
            |error| {
                self.state.store_lifecycle(ProbeLifecycleState::Faulted);
                Err(error)
            },
        )
    }
}

#[derive(Default)]
struct ProbeState {
    links: Mutex<Vec<AttachedProgramLink>>,
    lifecycle: AtomicU8,
    generation: AtomicU64,
}

struct AttachedProgramLink {
    program_name: &'static str,
    link_id: TracePointLinkId,
}

impl ProbeState {
    fn store_lifecycle(&self, state: ProbeLifecycleState) {
        self.lifecycle.store(state as u8, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuxiliaryProbeMetadata {
    program_name: &'static str,
    category: &'static str,
    tracepoint: &'static str,
}

impl AuxiliaryProbeMetadata {
    const fn from_spec(spec: &AuxiliaryBpfProgramSpec) -> Self {
        Self {
            program_name: spec.program_name,
            category: spec.category,
            tracepoint: spec.tracepoint,
        }
    }
}

#[derive(Clone)]
struct AuxiliaryProbeHandle {
    metadata: AuxiliaryProbeMetadata,
    bpf: Option<Arc<Mutex<Ebpf>>>,
    link_id: Arc<Mutex<Option<TracePointLinkId>>>,
}

impl AuxiliaryProbeHandle {
    fn new(metadata: AuxiliaryProbeMetadata, bpf: Option<Arc<Mutex<Ebpf>>>) -> Self {
        Self {
            metadata,
            bpf,
            link_id: Arc::new(Mutex::new(None)),
        }
    }

    async fn attach(&self) -> Result<(), SensorManagerError> {
        let mut link_slot = self.link_id.lock().await;
        if link_slot.is_some() {
            drop(link_slot);
            return Ok(());
        }

        let Some(bpf) = self.bpf.clone() else {
            drop(link_slot);
            return Err(SensorManagerError::ObjectNotLoaded);
        };

        let link = {
            let mut bpf_guard = bpf.lock().await;
            let link = {
                let program = tracepoint_program_mut_by_name(&mut bpf_guard, self.metadata)?;
                if let Err(error) = program.load()
                    && !matches!(error, ProgramError::AlreadyLoaded)
                {
                    return Err(SensorManagerError::AuxiliaryProgram {
                        program_name: self.metadata.program_name,
                        operation: "load",
                        source: error,
                    });
                }

                program
                    .attach(self.metadata.category, self.metadata.tracepoint)
                    .map_err(|source| SensorManagerError::AuxiliaryProgram {
                        program_name: self.metadata.program_name,
                        operation: "attach",
                        source,
                    })?
            };
            drop(bpf_guard);
            link
        };

        *link_slot = Some(link);
        drop(link_slot);
        Ok(())
    }

    async fn detach(&self) -> Result<(), SensorManagerError> {
        let mut link_slot = self.link_id.lock().await;
        let Some(link_id) = link_slot.take() else {
            drop(link_slot);
            return Ok(());
        };

        let Some(bpf) = self.bpf.clone() else {
            *link_slot = Some(link_id);
            drop(link_slot);
            return Err(SensorManagerError::ObjectNotLoaded);
        };

        let detach_result = {
            let mut bpf_guard = bpf.lock().await;
            let detach_result = {
                let program = tracepoint_program_mut_by_name(&mut bpf_guard, self.metadata)?;
                program.detach(link_id)
            };
            drop(bpf_guard);
            detach_result
        };

        detach_result.map_err(|source| SensorManagerError::AuxiliaryProgram {
            program_name: self.metadata.program_name,
            operation: "detach",
            source,
        })
    }
}

/// Summary of the best-effort `/proc` bootstrap used to seed `PPID_BY_TGID`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcPpidBootstrapReport {
    /// Number of numeric `/proc/<pid>` directories discovered.
    pub discovered_processes: usize,
    /// Number of process-TGID → parent-process-TGID entries inserted into the
    /// kernel hash map.
    pub inserted_entries: usize,
    /// Number of processes skipped because `/proc/<pid>/status` disappeared or
    /// could not be read while scanning.
    pub skipped_unreadable_statuses: usize,
    /// Number of status files that lacked a parseable `PPid:` field.
    pub skipped_missing_ppid: usize,
    /// Number of insert attempts that failed, usually because the bounded
    /// 65,536-entry map was already full.
    pub failed_inserts: usize,
}

/// Top-level owner for the sensor's loaded eBPF object and probe handles.
///
/// The manager wraps Aya's `Ebpf` value in a Tokio `Mutex` because Aya exposes a
/// mutable API for loading, attaching, detaching, and map access. The daemon is
/// asynchronous, so a Tokio mutex avoids blocking executor worker threads while
/// still serializing every mutation of the BPF object.
pub struct SensorManager {
    bpf: Option<Arc<Mutex<Ebpf>>>,
    probes: HashMap<SyscallType, ProbeHandle>,
    support_probes: Vec<AuxiliaryProbeHandle>,
    object_path: Option<PathBuf>,
}

impl SensorManager {
    /// Construct a manager from an already-loaded Aya `Ebpf` object.
    ///
    /// This constructor keeps the public API mock-friendly for future tests and
    /// daemon wiring that want to size maps or inject custom loader behavior
    /// before handing object ownership to the lifecycle manager.
    #[must_use]
    pub fn from_bpf(bpf: Ebpf) -> Self {
        Self::from_bpf_parts(Some(Arc::new(Mutex::new(bpf))), None)
    }

    /// Construct a metadata-only manager whose handles start detached.
    ///
    /// This is used by non-privileged tests and by API layers that need to
    /// enumerate supported probes before the daemon has loaded its BPF object.
    #[must_use]
    pub fn from_unloaded_specs() -> Self {
        Self::from_bpf_parts(None, None)
    }

    /// Build and load the default CO-RE/BTF eBPF object.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError` if the nested eBPF build fails or Aya cannot
    /// load the resulting ELF object.
    pub fn load_default_object() -> Result<Self, SensorManagerError> {
        Self::load_default_object_with_config(&Config::default())
    }

    /// Build and load the default CO-RE/BTF eBPF object using runtime config.
    ///
    /// The `ring_buffer_size_pages` field is translated to Aya's byte-sized
    /// `EVENTS` map override before the object is loaded, which is what makes
    /// a 4-page validation run create a 16 KiB ring buffer instead of the
    /// eBPF source's large default development capacity.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError` if the nested eBPF build fails, the
    /// configured page count overflows the 32-bit byte-size conversion, or Aya
    /// cannot load the resulting ELF object.
    pub fn load_default_object_with_config(config: &Config) -> Result<Self, SensorManagerError> {
        let object = build_ebpf_object().map_err(SensorManagerError::Build)?;
        Self::load_from_file_with_config(object, config)
    }

    /// Load a previously built CO-RE/BTF eBPF object from disk.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError::Load` when Aya cannot parse or load the
    /// object file. Kernel verifier failures for individual programs are
    /// reported later by `attach_probes` or per-probe `attach`.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, SensorManagerError> {
        Self::load_from_file_with_config(path, &Config::default())
    }

    /// Load a previously built CO-RE/BTF eBPF object from disk using runtime
    /// config to size the `EVENTS` ring buffer before map creation.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError::Load` when Aya cannot parse or load the
    /// object file, or `SensorManagerError::RingBufferSizeOverflow` when the
    /// configured page count cannot be represented as a byte-sized Aya map.
    pub fn load_from_file_with_config(
        path: impl AsRef<Path>,
        config: &Config,
    ) -> Result<Self, SensorManagerError> {
        let path = path.as_ref().to_path_buf();
        let mut loader = EbpfLoader::new();
        let btf = Btf::from_sys_fs().ok();
        if let Some(btf) = btf.as_ref() {
            loader.btf(Some(btf));
        }
        configure_events_ringbuf_on_loader(&mut loader, config.ring_buffer_size_pages)?;
        let bpf = loader.load_file(&path).map_err(SensorManagerError::Load)?;
        Ok(Self::from_bpf_parts(
            Some(Arc::new(Mutex::new(bpf))),
            Some(path),
        ))
    }

    /// Return the canonical FR-S01 probe ordering.
    #[must_use]
    pub const fn default_probe_types() -> &'static [SyscallType; 4] {
        &DEFAULT_PROBE_TYPES
    }

    /// Return compiled metadata for a supported syscall probe.
    #[must_use]
    pub fn probe_metadata(syscall_type: SyscallType) -> Option<ProbeMetadata> {
        let program_specs = probe_program_specs(syscall_type);
        let primary_spec = *program_specs.first()?;
        Some(ProbeMetadata::from_primary_spec(
            syscall_type,
            primary_spec,
            program_specs,
        ))
    }

    /// Return the loaded eBPF object path, when this manager owns one.
    #[must_use]
    pub fn object_path(&self) -> Option<&Path> {
        self.object_path.as_deref()
    }

    /// Return clones of every managed probe handle.
    #[must_use]
    pub fn probe_handles(&self) -> Vec<ProbeHandle> {
        DEFAULT_PROBE_TYPES
            .iter()
            .filter_map(|syscall_type| self.probes.get(syscall_type).cloned())
            .collect()
    }

    /// Return a clone of one managed probe handle.
    #[must_use]
    pub fn probe_handle(&self, syscall_type: SyscallType) -> Option<ProbeHandle> {
        self.probes.get(&syscall_type).cloned()
    }

    /// Attach all four default probes and return one handle per probe.
    ///
    /// # Errors
    ///
    /// Returns the first `SensorManagerError` encountered while loading or
    /// attaching a probe. Any probes attached before the error remain tracked by
    /// the manager so callers can invoke `detach_probes` for cleanup.
    pub async fn attach_probes(&self) -> Result<Vec<ProbeHandle>, SensorManagerError> {
        self.attach_support_probes().await?;
        for syscall_type in DEFAULT_PROBE_TYPES {
            let handle = self
                .probe_handle(syscall_type)
                .ok_or(SensorManagerError::UnknownProbe(syscall_type))?;
            handle.attach().await?;
        }
        self.bootstrap_ppid_map_from_proc().await?;
        Ok(self.probe_handles())
    }

    /// Attach one named probe without changing the others.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError::UnknownProbe` for unsupported syscalls or
    /// the per-probe attach error from Aya/kernel verification.
    pub async fn attach_probe(
        &self,
        syscall_type: SyscallType,
    ) -> Result<ProbeHandle, SensorManagerError> {
        let handle = self
            .probe_handle(syscall_type)
            .ok_or(SensorManagerError::UnknownProbe(syscall_type))?;
        if self.bpf.is_some() {
            self.attach_support_probes().await?;
        }
        handle.attach().await?;
        Ok(handle)
    }

    /// Detach one named probe without changing the other three.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError::UnknownProbe` for unsupported syscalls or
    /// the per-probe detach error from Aya. Detaching an already-detached probe
    /// is considered successful and still returns its handle.
    pub async fn detach_probe(
        &self,
        syscall_type: SyscallType,
    ) -> Result<ProbeHandle, SensorManagerError> {
        let handle = self
            .probe_handle(syscall_type)
            .ok_or(SensorManagerError::UnknownProbe(syscall_type))?;
        handle.detach().await?;
        if !self.any_user_probe_attached() {
            self.detach_support_probes().await?;
        }
        Ok(handle)
    }

    /// Detach every managed probe while continuing after individual failures.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError::DetachFailures` if one or more probes failed
    /// to detach. The included report records which probes succeeded or failed.
    pub async fn detach_probes(&self) -> Result<DetachReport, SensorManagerError> {
        let mut report = DetachReport::default();
        for handle in self.probe_handles() {
            report.attempted += 1;
            let was_attached = handle.lifecycle_state() == ProbeLifecycleState::Attached;
            match handle.detach().await {
                Ok(()) if was_attached => report.detached += 1,
                Ok(()) => report.already_detached += 1,
                Err(error) => report.failures.push(ProbeOperationFailure {
                    syscall_type: handle.syscall_type(),
                    message: error.to_string(),
                }),
            }
        }
        self.detach_support_probes().await?;

        if report.failures.is_empty() {
            Ok(report)
        } else {
            Err(SensorManagerError::DetachFailures(report))
        }
    }

    /// Reload probes by detaching the current links and reattaching all four.
    ///
    /// # Errors
    ///
    /// Returns a detach failure report if cleanup fails, or an attach error if
    /// any reattach fails. Successful reloads include attach generations before
    /// and after so tests can prove reattach creates fresh links.
    pub async fn reload_probes(&self) -> Result<ReloadReport, SensorManagerError> {
        let before_generations = self.attach_generations();
        let detach_report = self.detach_probes().await?;
        self.attach_probes().await?;
        Ok(ReloadReport {
            detach_report,
            before_generations,
            after_generations: self.attach_generations(),
        })
    }

    /// Read the current kernel-side drop and runtime-fault counters.
    ///
    /// This is the public sensor-facing surface that later daemon health code
    /// will call for VAL-SENSOR-013/014/019. The method is async because it
    /// must serialize access to Aya's mutable map APIs through the same Tokio
    /// mutex used by attach/detach operations.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError::ObjectNotLoaded` for metadata-only
    /// managers, or `SensorManagerError::KernelCounterRead` when the expected
    /// maps are missing or Aya cannot read them.
    pub async fn kernel_counters(&self) -> Result<KernelCounterSnapshot, SensorManagerError> {
        let bpf = self
            .bpf
            .as_ref()
            .ok_or(SensorManagerError::ObjectNotLoaded)?;
        let mut bpf = bpf.lock().await;
        KernelCounterMaps::snapshot_from_bpf(&mut bpf)
            .map_err(SensorManagerError::KernelCounterRead)
    }

    /// Seed the kernel `PPID_BY_TGID` map from the current `/proc` process list.
    ///
    /// The support tracepoints only observe forks that happen after the sensor
    /// attaches. This best-effort bootstrap fills the bounded
    /// process-TGID → parent-process-TGID index for already-running processes
    /// by reading each `/proc/<pid>/status` `PPid:` field once and inserting
    /// `(pid, ppid)` into the kernel map. Threads do not need separate entries
    /// because syscall probes always look up by the current TGID. There is
    /// still a small race window between attaching the support tracepoints and
    /// finishing this scan: a process could fork and exec before its
    /// `/proc/<pid>/status` file is visited, in which case the syscall event
    /// will temporarily report `ppid=0`. The feature explicitly accepts that
    /// best-effort gap.
    ///
    /// # Errors
    ///
    /// Returns `SensorManagerError::ObjectNotLoaded` for metadata-only managers,
    /// `SensorManagerError::ProcStatusScan` if the top-level `/proc` walk fails,
    /// or map-related errors if the `PPID_BY_TGID` map is unexpectedly missing.
    pub async fn bootstrap_ppid_map_from_proc(
        &self,
    ) -> Result<ProcPpidBootstrapReport, SensorManagerError> {
        let bpf = self
            .bpf
            .as_ref()
            .ok_or(SensorManagerError::ObjectNotLoaded)?;
        bootstrap_loaded_bpf_ppid_map(&mut *bpf.lock().await)
    }

    /// Drain currently available raw records from the `EVENTS` ring buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if no BPF object is loaded, if another lifecycle
    /// operation currently holds the BPF mutex, if the ring-buffer map is
    /// missing, or if Aya cannot mmap the map.
    pub fn drain_raw_events(&self) -> Result<Vec<RawSyscallEvent>, SensorManagerError> {
        let bpf = self
            .bpf
            .as_ref()
            .ok_or(SensorManagerError::ObjectNotLoaded)?;
        let mut records = Vec::new();
        {
            let mut bpf = bpf.try_lock().map_err(|_| SensorManagerError::BpfBusy)?;
            let mut ring = RingBuf::try_from(
                bpf.map_mut(EVENT_RINGBUF_MAP)
                    .ok_or(SensorManagerError::MissingRingBufferMap)?,
            )
            .map_err(SensorManagerError::Map)?;
            while records.len() < MAX_RAW_DRAIN_BATCH {
                let Some(item) = ring.next() else {
                    break;
                };
                if item.len() == core::mem::size_of::<RawSyscallEvent>() {
                    let mut event = RawSyscallEvent::default();
                    // SAFETY: The destination is a valid `RawSyscallEvent`,
                    // and the length check above proves the ring-buffer item
                    // contains exactly one event worth of initialized bytes.
                    // Copying avoids creating an aligned reference to Aya's
                    // byte slice.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            item.as_ptr(),
                            (&raw mut event).cast::<u8>(),
                            core::mem::size_of::<RawSyscallEvent>(),
                        );
                    }
                    records.push(event);
                }
            }
            drop(ring);
            drop(bpf);
        }
        Ok(records)
    }

    fn from_bpf_parts(bpf: Option<Arc<Mutex<Ebpf>>>, object_path: Option<PathBuf>) -> Self {
        let probes = DEFAULT_PROBE_TYPES
            .iter()
            .filter_map(|syscall_type| {
                let metadata = Self::probe_metadata(*syscall_type)?;
                Some((*syscall_type, ProbeHandle::new(metadata, bpf.clone())))
            })
            .collect();
        let support_probes = AUXILIARY_BPF_PROGRAMS
            .iter()
            .map(AuxiliaryProbeMetadata::from_spec)
            .map(|metadata| AuxiliaryProbeHandle::new(metadata, bpf.clone()))
            .collect();

        Self {
            bpf,
            probes,
            support_probes,
            object_path,
        }
    }

    fn attach_generations(&self) -> HashMap<SyscallType, u64> {
        self.probe_handles()
            .into_iter()
            .map(|handle| (handle.syscall_type(), handle.attach_generation()))
            .collect()
    }

    fn any_user_probe_attached(&self) -> bool {
        self.probe_handles()
            .iter()
            .any(|handle| handle.lifecycle_state() == ProbeLifecycleState::Attached)
    }

    async fn attach_support_probes(&self) -> Result<(), SensorManagerError> {
        for handle in &self.support_probes {
            handle.attach().await?;
        }
        Ok(())
    }

    async fn detach_support_probes(&self) -> Result<(), SensorManagerError> {
        for handle in &self.support_probes {
            handle.detach().await?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcPpidEntry {
    pid: u32,
    parent_tgid: u32,
}

#[derive(Debug)]
struct ProcStatusScan {
    entries: Vec<ProcPpidEntry>,
    report: ProcPpidBootstrapReport,
}

fn collect_proc_ppid_entries(proc_root: &Path) -> io::Result<ProcStatusScan> {
    let mut entries = Vec::with_capacity(PPID_INDEX_MAX_ENTRIES.min(4_096));
    let mut report = ProcPpidBootstrapReport::default();

    for entry_result in fs::read_dir(proc_root)? {
        let Ok(entry) = entry_result else {
            report.skipped_unreadable_statuses += 1;
            continue;
        };
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            report.skipped_unreadable_statuses += 1;
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };
        report.discovered_processes += 1;

        let status_path = entry.path().join("status");
        let status = match fs::read_to_string(&status_path) {
            Ok(status) => status,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                report.skipped_unreadable_statuses += 1;
                continue;
            }
            Err(error) => return Err(error),
        };

        let Some(parent_tgid) = parse_proc_status_ppid(&status) else {
            report.skipped_missing_ppid += 1;
            continue;
        };
        if pid == 0 {
            report.skipped_missing_ppid += 1;
            continue;
        }

        // `/proc/<pid>/status` exposes the process-level `PPid:` once for the
        // whole thread group, and every thread reports syscalls under the same
        // TGID. A single `(pid, ppid)` insert is therefore sufficient for the
        // kernel lookup contract.
        entries.push(ProcPpidEntry { pid, parent_tgid });
    }

    Ok(ProcStatusScan { entries, report })
}

fn parse_proc_status_ppid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok())
}

fn populate_ppid_map(
    bpf: &mut Ebpf,
    entries: Vec<ProcPpidEntry>,
    report: &mut ProcPpidBootstrapReport,
) -> Result<(), SensorManagerError> {
    let mut ppid_map = AyaHashMap::<_, u32, u32>::try_from(
        bpf.map_mut(PPID_BY_TGID_MAP)
            .ok_or(SensorManagerError::MissingPpidIndexMap)?,
    )
    .map_err(SensorManagerError::Map)?;

    for entry in entries {
        match ppid_map.insert(entry.pid, entry.parent_tgid, 0) {
            Ok(()) => report.inserted_entries += 1,
            Err(_) => report.failed_inserts += 1,
        }
    }

    Ok(())
}

/// Best-effort `/proc` bootstrap for callers that already hold a mutable Aya
/// `Ebpf` object outside `SensorManager`.
///
/// This is used by privileged harnesses that attach programs manually but still
/// want to seed the shared process-TGID → parent-process-TGID index before they
/// start observing events.
///
/// # Errors
///
/// Returns `SensorManagerError::ProcStatusScan` if the top-level `/proc` walk
/// fails or a map-related error if the `PPID_BY_TGID` map is missing.
pub(crate) fn bootstrap_loaded_bpf_ppid_map(
    bpf: &mut Ebpf,
) -> Result<ProcPpidBootstrapReport, SensorManagerError> {
    let ProcStatusScan {
        entries,
        mut report,
    } = collect_proc_ppid_entries(Path::new("/proc"))
        .map_err(SensorManagerError::ProcStatusScan)?;
    populate_ppid_map(bpf, entries, &mut report)?;
    Ok(report)
}

/// Summary returned by `SensorManager::detach_probes`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DetachReport {
    /// Number of probe handles visited by the bulk detach operation.
    pub attempted: usize,
    /// Number of handles that transitioned from attached to detached.
    pub detached: usize,
    /// Number of handles that were already detached before the call.
    pub already_detached: usize,
    /// Per-probe failures collected after trying all handles.
    pub failures: Vec<ProbeOperationFailure>,
}

/// One per-probe lifecycle operation failure captured in a report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeOperationFailure {
    /// Syscall whose probe operation failed.
    pub syscall_type: SyscallType,
    /// Human-readable error returned by Aya or the manager.
    pub message: String,
}

/// Summary returned by `SensorManager::reload_probes`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadReport {
    /// Detach outcomes from the first half of the reload.
    pub detach_report: DetachReport,
    /// Per-probe attach generations before reload began.
    pub before_generations: HashMap<SyscallType, u64>,
    /// Per-probe attach generations after reload completed.
    pub after_generations: HashMap<SyscallType, u64>,
}

/// Errors produced by sensor lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum SensorManagerError {
    /// The nested eBPF package failed to build.
    #[error(transparent)]
    Build(BuildError),
    /// Aya could not load the BTF-enabled ELF object.
    #[error(transparent)]
    Load(EbpfError),
    /// The caller requested a syscall that this sensor does not implement.
    #[error("unsupported probe for syscall {0:?}")]
    UnknownProbe(SyscallType),
    /// A handle was asked to attach/detach before an eBPF object was loaded.
    #[error("sensor manager does not have a loaded BPF object")]
    ObjectNotLoaded,
    /// The expected eBPF program symbol was missing from the object.
    #[error("missing eBPF program {program_name} for {syscall_type:?}")]
    MissingProgram {
        /// Syscall whose program was missing.
        syscall_type: SyscallType,
        /// Expected Aya program symbol.
        program_name: &'static str,
    },
    /// Aya failed to load, attach, or detach a tracepoint program.
    #[error("{operation} failed for {syscall_type:?}: {source}")]
    Program {
        /// Syscall whose probe operation failed.
        syscall_type: SyscallType,
        /// Operation being attempted.
        operation: &'static str,
        /// Original Aya program error.
        #[source]
        source: ProgramError,
    },
    /// The expected support tracepoint program symbol was missing from the object.
    #[error("missing support eBPF program {program_name}")]
    MissingAuxiliaryProgram {
        /// Expected Aya program symbol.
        program_name: &'static str,
    },
    /// Aya failed to load, attach, or detach a support tracepoint program.
    #[error("{operation} failed for support program {program_name}: {source}")]
    AuxiliaryProgram {
        /// Support-program symbol being operated on.
        program_name: &'static str,
        /// Operation being attempted.
        operation: &'static str,
        /// Original Aya program error.
        #[source]
        source: ProgramError,
    },
    /// One or more probes failed during a best-effort bulk detach.
    #[error("one or more probes failed to detach: {0:?}")]
    DetachFailures(DetachReport),
    /// The shared BPF object was busy during a synchronous ring-buffer drain.
    #[error("BPF object is busy with another lifecycle operation")]
    BpfBusy,
    /// The compiled object did not contain the expected ring-buffer map.
    #[error("missing EVENTS ring-buffer map")]
    MissingRingBufferMap,
    /// The compiled object did not contain the expected process-TGID →
    /// parent-process-TGID index map.
    #[error("missing PPID_BY_TGID bootstrap map")]
    MissingPpidIndexMap,
    /// Aya could not construct a userspace ring-buffer view.
    #[error(transparent)]
    Map(MapError),
    /// The configured ring-buffer page count overflowed the byte-size
    /// conversion required by Aya's loader API.
    #[error(
        "ring_buffer_size_pages={pages} overflows the 4096-byte page conversion used for the EVENTS ring buffer"
    )]
    RingBufferSizeOverflow {
        /// The page count that could not be converted into a 32-bit byte size.
        pages: u32,
    },
    /// Aya could not read one of the expected kernel counter maps.
    #[error(transparent)]
    KernelCounterRead(KernelCounterReadError),
    /// The top-level `/proc` scan failed before the best-effort bootstrap
    /// could gather candidate process-TGID → parent-process-TGID entries.
    #[error("failed to scan /proc for PPID bootstrap data: {0}")]
    ProcStatusScan(io::Error),
}

fn tracepoint_program_mut_by_program_name<'a>(
    bpf: &'a mut Ebpf,
    program_name: &'static str,
    syscall_type: SyscallType,
) -> Result<&'a mut TracePoint, SensorManagerError> {
    bpf.program_mut(program_name)
        .ok_or(SensorManagerError::MissingProgram {
            syscall_type,
            program_name,
        })?
        .try_into()
        .map_err(|source| SensorManagerError::Program {
            syscall_type,
            operation: "select tracepoint program",
            source,
        })
}

fn tracepoint_program_mut_by_name(
    bpf: &mut Ebpf,
    metadata: AuxiliaryProbeMetadata,
) -> Result<&mut TracePoint, SensorManagerError> {
    bpf.program_mut(metadata.program_name)
        .ok_or(SensorManagerError::MissingAuxiliaryProgram {
            program_name: metadata.program_name,
        })?
        .try_into()
        .map_err(|source| SensorManagerError::AuxiliaryProgram {
            program_name: metadata.program_name,
            operation: "select tracepoint program",
            source,
        })
}

fn rollback_attached_program_links(
    bpf: &mut Ebpf,
    syscall_type: SyscallType,
    attached_links: &mut Vec<AttachedProgramLink>,
) {
    while let Some(AttachedProgramLink {
        program_name,
        link_id,
    }) = attached_links.pop()
    {
        if let Ok(program) = tracepoint_program_mut_by_program_name(bpf, program_name, syscall_type)
        {
            let _ = program.detach(link_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EVENT_RINGBUF_MAP, ProcPpidBootstrapReport, collect_proc_ppid_entries,
        configure_events_ringbuf_on_loader, parse_proc_status_ppid,
    };
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Default)]
    struct RecordingLoader {
        configured_maps: Vec<(&'static str, u32)>,
    }

    impl super::RingBufferMapSizer for RecordingLoader {
        fn set_max_entries(&mut self, map_name: &'static str, max_entries: u32) {
            self.configured_maps.push((map_name, max_entries));
        }
    }

    #[test]
    fn sensor_manager_configures_events_ringbuf_bytes_from_requested_pages() {
        let mut loader = RecordingLoader::default();

        let byte_size =
            configure_events_ringbuf_on_loader(&mut loader, 4).expect("four pages should fit");

        assert_eq!(byte_size, 16 * 1024);
        assert_eq!(loader.configured_maps, vec![(EVENT_RINGBUF_MAP, 16 * 1024)]);
    }

    #[test]
    fn parse_proc_status_ppid_extracts_numeric_parent_pid() {
        let status = "Name:\tsleep\nPid:\t4242\nPPid:\t1337\nState:\tS (sleeping)\n";

        assert_eq!(parse_proc_status_ppid(status), Some(1337));
    }

    #[test]
    fn collect_proc_ppid_entries_reads_one_process_tgid_entry_per_pid() {
        let temp_root = temp_proc_root("ppid-bootstrap");
        fs::create_dir_all(temp_root.join("101")).expect("numeric proc dir is created");
        fs::write(
            temp_root.join("101").join("status"),
            "Name:\talpha\nPid:\t101\nPPid:\t7\n",
        )
        .expect("valid status is written");
        fs::create_dir_all(temp_root.join("1")).expect("init proc dir is created");
        fs::write(
            temp_root.join("1").join("status"),
            "Name:\tinit\nPid:\t1\nPPid:\t0\n",
        )
        .expect("root status is written");
        fs::create_dir_all(temp_root.join("202")).expect("second numeric proc dir is created");
        fs::write(
            temp_root.join("202").join("status"),
            "Name:\tbeta\nPid:\t202\nState:\tR (running)\n",
        )
        .expect("invalid status is written");
        fs::create_dir_all(temp_root.join("self")).expect("non-numeric proc dir is created");

        let mut scan = collect_proc_ppid_entries(&temp_root).expect("temp proc tree is readable");
        scan.entries.sort_by_key(|entry| entry.pid);

        assert_eq!(
            scan.report,
            ProcPpidBootstrapReport {
                discovered_processes: 3,
                inserted_entries: 0,
                skipped_unreadable_statuses: 0,
                skipped_missing_ppid: 1,
                failed_inserts: 0,
            }
        );
        assert_eq!(scan.entries.len(), 2);
        assert_eq!(scan.entries[0].pid, 1);
        assert_eq!(scan.entries[0].parent_tgid, 0);
        assert_eq!(scan.entries[1].pid, 101);
        assert_eq!(scan.entries[1].parent_tgid, 7);

        fs::remove_dir_all(temp_root).expect("temp proc tree is removed");
    }

    fn temp_proc_root(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after unix epoch")
            .as_nanos();
        Path::new("/tmp").join(format!("mini-edr-{test_name}-{unique}"))
    }
}
