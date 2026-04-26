//! Dynamic eBPF probe lifecycle management for the Mini-EDR sensor.
//!
//! SDD §4.1.1 names `SensorManager` as the userspace owner of the Aya `Ebpf`
//! object and `ProbeHandle` values as the API used to detach or reattach one
//! tracepoint at runtime. This module implements FR-S05 while preserving the
//! FR-S04 CO-RE/BTF contract: the manager loads the same BTF-enabled object
//! produced by `bpf-linker --btf` and never rebuilds per running kernel.

use crate::{
    bpf::{BPF_PROGRAMS, BpfProgramSpec, BuildError, EVENT_RINGBUF_MAP, build_ebpf_object},
    kernel_metrics::{KernelCounterMaps, KernelCounterReadError, KernelCounterSnapshot},
    raw_event::RawSyscallEvent,
};
use aya::{
    Btf, Ebpf, EbpfError, EbpfLoader,
    maps::{MapError, RingBuf},
    programs::{ProgramError, TracePoint, trace_point::TracePointLinkId},
};
use mini_edr_common::{Config, SyscallType};
use std::{
    collections::HashMap,
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
}

impl ProbeMetadata {
    const fn from_spec(spec: &BpfProgramSpec) -> Self {
        Self {
            syscall_type: syscall_type_for_spec(spec),
            program_name: spec.program_name,
            category: spec.category,
            tracepoint: spec.tracepoint,
        }
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
        let mut link_slot = self.state.link_id.lock().await;
        if link_slot.is_some() {
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
        let link = {
            let mut bpf_guard = bpf.lock().await;
            let link = {
                let program = match tracepoint_program_mut(&mut bpf_guard, self.metadata) {
                    Ok(program) => program,
                    Err(error) => {
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
                    self.state.store_lifecycle(ProbeLifecycleState::Faulted);
                    return Err(SensorManagerError::Program {
                        syscall_type: self.metadata.syscall_type,
                        operation: "load",
                        source: error,
                    });
                }

                match program.attach(self.metadata.category, self.metadata.tracepoint) {
                    Ok(link) => link,
                    Err(source) => {
                        self.state.store_lifecycle(ProbeLifecycleState::Faulted);
                        return Err(SensorManagerError::Program {
                            syscall_type: self.metadata.syscall_type,
                            operation: "attach",
                            source,
                        });
                    }
                }
            };
            drop(bpf_guard);
            link
        };
        *link_slot = Some(link);
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
        let mut link_slot = self.state.link_id.lock().await;
        let Some(link_id) = link_slot.take() else {
            self.state.store_lifecycle(ProbeLifecycleState::Detached);
            drop(link_slot);
            return Ok(());
        };

        let Some(bpf) = self.bpf.clone() else {
            *link_slot = Some(link_id);
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
        let detach_result = {
            let mut bpf_guard = bpf.lock().await;
            let detach_result = {
                let program = tracepoint_program_mut(&mut bpf_guard, self.metadata)?;
                program.detach(link_id)
            };
            drop(bpf_guard);
            detach_result
        };
        match detach_result {
            Ok(()) => {
                drop(link_slot);
                self.state.store_lifecycle(ProbeLifecycleState::Detached);
                Ok(())
            }
            Err(source) => {
                drop(link_slot);
                self.state.store_lifecycle(ProbeLifecycleState::Faulted);
                Err(SensorManagerError::Program {
                    syscall_type: self.metadata.syscall_type,
                    operation: "detach",
                    source,
                })
            }
        }
    }
}

#[derive(Default)]
struct ProbeState {
    link_id: Mutex<Option<TracePointLinkId>>,
    lifecycle: AtomicU8,
    generation: AtomicU64,
}

impl ProbeState {
    fn store_lifecycle(&self, state: ProbeLifecycleState) {
        self.lifecycle.store(state as u8, Ordering::Release);
    }
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
        BPF_PROGRAMS
            .iter()
            .map(ProbeMetadata::from_spec)
            .find(|metadata| metadata.syscall_type == syscall_type)
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
        for syscall_type in DEFAULT_PROBE_TYPES {
            self.attach_probe(syscall_type).await?;
        }
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

        Self {
            bpf,
            probes,
            object_path,
        }
    }

    fn attach_generations(&self) -> HashMap<SyscallType, u64> {
        self.probe_handles()
            .into_iter()
            .map(|handle| (handle.syscall_type(), handle.attach_generation()))
            .collect()
    }
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
    /// One or more probes failed during a best-effort bulk detach.
    #[error("one or more probes failed to detach: {0:?}")]
    DetachFailures(DetachReport),
    /// The shared BPF object was busy during a synchronous ring-buffer drain.
    #[error("BPF object is busy with another lifecycle operation")]
    BpfBusy,
    /// The compiled object did not contain the expected ring-buffer map.
    #[error("missing EVENTS ring-buffer map")]
    MissingRingBufferMap,
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
}

fn tracepoint_program_mut(
    bpf: &mut Ebpf,
    metadata: ProbeMetadata,
) -> Result<&mut TracePoint, SensorManagerError> {
    bpf.program_mut(metadata.program_name)
        .ok_or(SensorManagerError::MissingProgram {
            syscall_type: metadata.syscall_type,
            program_name: metadata.program_name,
        })?
        .try_into()
        .map_err(|source| SensorManagerError::Program {
            syscall_type: metadata.syscall_type,
            operation: "select tracepoint program",
            source,
        })
}

const fn syscall_type_for_spec(spec: &BpfProgramSpec) -> SyscallType {
    match spec.raw_type {
        crate::raw_event::RawSyscallType::Execve => SyscallType::Execve,
        crate::raw_event::RawSyscallType::Openat => SyscallType::Openat,
        crate::raw_event::RawSyscallType::Connect => SyscallType::Connect,
        crate::raw_event::RawSyscallType::Clone => SyscallType::Clone,
    }
}

#[cfg(test)]
mod tests {
    use super::{EVENT_RINGBUF_MAP, configure_events_ringbuf_on_loader};

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
}
