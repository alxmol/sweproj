//! `/proc` readers used by the telemetry enrichment stage.
//!
//! Per SDD §4.1.2 and FR-P02, the pipeline enriches raw sensor events by
//! reading `/proc/<pid>/status`, `exe`, `cgroup`, and `stat`. The key design
//! constraint is that `/proc` is not a snapshot: a process can exit between the
//! kernel event and userspace enrichment. That race is normal and must surface
//! as a structured `NotFound` result rather than a panic.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Parsed subset of `/proc/<pid>/status` needed for enrichment and ancestry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcStatus {
    /// Kernel process name from the `Name:` line.
    pub name: String,
    /// Thread-group identifier from the `Tgid:` line.
    pub tgid: u32,
    /// Parent process identifier from the `PPid:` line.
    pub ppid: u32,
    /// Real UID from the first field of `Uid:`.
    pub uid: u32,
}

/// Parsed subset of `/proc/<pid>/stat` needed for ancestry reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcStat {
    /// PID field at the start of the stat record.
    pub pid: u32,
    /// Command name stored between the first `(` and the matching `)`.
    pub comm: String,
    /// Single-letter scheduler state that follows `comm`.
    pub state: char,
    /// Parent process identifier from field 4.
    pub ppid: u32,
    /// Kernel clock ticks since boot when the process started (field 22).
    pub start_time_ticks: u64,
}

/// Structured `/proc` mount visibility information derived from `/proc/mounts`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcHidePidSetting {
    /// `hidepid` mode reported by the procfs mount. `0` means unrestricted.
    pub mode: u32,
    /// Optional group override that can bypass `hidepid` restrictions.
    pub gid: Option<u32>,
}

impl ProcHidePidSetting {
    /// Return whether the procfs mount is using any `hidepid` restriction.
    #[must_use]
    pub const fn is_active(self) -> bool {
        self.mode > 0
    }
}

/// Structured failures for `/proc` reads during enrichment.
#[derive(Debug, thiserror::Error)]
pub enum ProcReadError {
    /// The process vanished before userspace could finish the read.
    #[error("pid {pid} disappeared before `{path}` could be read")]
    NotFound {
        /// Process identifier being inspected.
        pid: u32,
        /// Specific `/proc` path that raced with process exit.
        path: String,
    },
    /// Procfs access is blocked, usually by `hidepid` or ownership policy.
    #[error("permission denied reading `{path}` for pid {pid}; /proc may be mounted with hidepid")]
    Permission {
        /// Process identifier being inspected.
        pid: u32,
        /// Specific `/proc` path that could not be inspected.
        path: String,
    },
    /// Any other transient or malformed-I/O failure.
    #[error("I/O error reading `{path}` for pid {pid}: {source}")]
    Io {
        /// Process identifier being inspected.
        pid: u32,
        /// Specific `/proc` path that failed.
        path: String,
        /// Underlying I/O error that should be logged by callers.
        #[source]
        source: std::io::Error,
    },
}

/// Reads `/proc` files for the pipeline enrichment stage.
#[derive(Debug)]
pub struct ProcReader {
    proc_root: PathBuf,
    hidepid: ProcHidePidSetting,
}

impl ProcReader {
    /// Construct a reader rooted at the host `/proc` mount.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the procfs mount metadata cannot be read.
    pub fn new() -> std::io::Result<Self> {
        Self::with_root("/proc")
    }

    /// Construct a reader rooted at an alternate procfs path, primarily for tests.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the procfs mount metadata cannot be read.
    pub fn with_root(proc_root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let proc_root = proc_root.into();
        let hidepid = Self::detect_hidepid(&proc_root)?;
        let reader = Self { proc_root, hidepid };
        reader.log_hidepid_warning();
        Ok(reader)
    }

    /// Return the detected `/proc` visibility policy.
    #[must_use]
    pub const fn hidepid_setting(&self) -> ProcHidePidSetting {
        self.hidepid
    }

    /// Read and parse `/proc/<pid>/status`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` when the process exits mid-read, `Permission` when
    /// procfs access is restricted, and `Io` for any other failure.
    pub fn read_status(&self, pid: u32) -> Result<ProcStatus, ProcReadError> {
        let path = self.proc_path(pid, "status");
        let contents = Self::read_proc_text(pid, &path)?;
        Self::parse_status(pid, &path, &contents)
    }

    /// Resolve `/proc/<pid>/exe` to the host-visible executable path.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` when the process exits mid-read, `Permission` when
    /// procfs access is restricted, and `Io` for any other failure.
    pub fn read_exe(&self, pid: u32) -> Result<PathBuf, ProcReadError> {
        let path = self.proc_path(pid, "exe");
        fs::read_link(&path).map_err(|source| Self::classify_io(pid, &path, source))
    }

    /// Read `/proc/<pid>/cgroup` as-is so container processes keep host-side hierarchy.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` when the process exits mid-read, `Permission` when
    /// procfs access is restricted, and `Io` for any other failure.
    pub fn read_cgroup(&self, pid: u32) -> Result<String, ProcReadError> {
        let path = self.proc_path(pid, "cgroup");
        Self::read_proc_text(pid, &path)
    }

    /// Read and parse `/proc/<pid>/stat`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` when the process exits mid-read, `Permission` when
    /// procfs access is restricted, and `Io` for any other failure.
    pub fn read_stat(&self, pid: u32) -> Result<ProcStat, ProcReadError> {
        let path = self.proc_path(pid, "stat");
        let contents = Self::read_proc_text(pid, &path)?;
        Self::parse_stat(pid, &path, &contents)
    }

    fn detect_hidepid(proc_root: &Path) -> std::io::Result<ProcHidePidSetting> {
        let mounts = fs::read_to_string(proc_root.join("mounts"))?;
        for line in mounts.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            if fields[1] == "/proc" && fields[2] == "proc" {
                return Ok(Self::parse_hidepid_options(fields[3]));
            }
        }

        Ok(ProcHidePidSetting { mode: 0, gid: None })
    }

    fn parse_hidepid_options(options: &str) -> ProcHidePidSetting {
        let mut hidepid = ProcHidePidSetting { mode: 0, gid: None };
        for option in options.split(',') {
            if let Some((key, value)) = option.split_once('=') {
                match key {
                    "hidepid" => {
                        hidepid.mode = value.parse().unwrap_or(0);
                    }
                    "gid" => {
                        hidepid.gid = value.parse().ok();
                    }
                    _ => {}
                }
            }
        }

        hidepid
    }

    fn log_hidepid_warning(&self) {
        if self.hidepid.is_active() {
            tracing::warn!(
                event = "proc_hidepid_detected",
                hidepid = self.hidepid.mode,
                gid = self.hidepid.gid,
                "procfs hidepid is active; ProcReader will return Permission errors for processes this uid cannot inspect"
            );
        }
    }

    fn proc_path(&self, pid: u32, name: &str) -> PathBuf {
        self.proc_root.join(pid.to_string()).join(name)
    }

    fn read_proc_text(pid: u32, path: &Path) -> Result<String, ProcReadError> {
        // `/proc` is fundamentally racy: the kernel may emit an event, schedule
        // userspace later, and drop the corresponding `/proc/<pid>` entries in
        // the meantime. Mapping ENOENT to `NotFound` makes that race explicit so
        // later pipeline stages can emit partial enrichment instead of panicking.
        fs::read_to_string(path).map_err(|source| Self::classify_io(pid, path, source))
    }

    fn classify_io(pid: u32, path: &Path, source: io::Error) -> ProcReadError {
        let path = path.display().to_string();
        match source.kind() {
            io::ErrorKind::NotFound => ProcReadError::NotFound { pid, path },
            io::ErrorKind::PermissionDenied => ProcReadError::Permission { pid, path },
            _ => ProcReadError::Io { pid, path, source },
        }
    }

    fn parse_status(
        process_id: u32,
        path: &Path,
        contents: &str,
    ) -> Result<ProcStatus, ProcReadError> {
        let mut name = None;
        let mut tgid = None;
        let mut parent_pid = None;
        let mut uid = None;

        for line in contents.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim();
                match key {
                    "Name" => name = Some(value.to_owned()),
                    "Tgid" => {
                        tgid = Some(
                            Self::parse_u32_field(value, "Tgid")
                                .map_err(|source| Self::classify_io(process_id, path, source))?,
                        );
                    }
                    "PPid" => {
                        parent_pid = Some(
                            Self::parse_u32_field(value, "PPid")
                                .map_err(|source| Self::classify_io(process_id, path, source))?,
                        );
                    }
                    "Uid" => {
                        uid = Some(
                            Self::parse_first_whitespace_u32(value, "Uid")
                                .map_err(|source| Self::classify_io(process_id, path, source))?,
                        );
                    }
                    _ => {}
                }
            }
        }

        Ok(ProcStatus {
            name: name.ok_or_else(|| Self::invalid_data(process_id, path, "missing Name field"))?,
            tgid: tgid.ok_or_else(|| Self::invalid_data(process_id, path, "missing Tgid field"))?,
            ppid: parent_pid
                .ok_or_else(|| Self::invalid_data(process_id, path, "missing PPid field"))?,
            uid: uid.ok_or_else(|| Self::invalid_data(process_id, path, "missing Uid field"))?,
        })
    }

    fn parse_stat(pid: u32, path: &Path, contents: &str) -> Result<ProcStat, ProcReadError> {
        // `/proc/<pid>/stat` is space-delimited except for `comm`, which is
        // wrapped in parentheses and may itself contain spaces. Parsing from the
        // outer parentheses is therefore the stable strategy that survives
        // command names like `sleep worker` without misaligning later fields.
        let open_paren = contents
            .find('(')
            .ok_or_else(|| Self::invalid_data(pid, path, "stat missing opening parenthesis"))?;
        let close_paren = contents
            .rfind(')')
            .ok_or_else(|| Self::invalid_data(pid, path, "stat missing closing parenthesis"))?;
        if close_paren <= open_paren {
            return Err(Self::invalid_data(
                pid,
                path,
                "stat command field parentheses are malformed",
            ));
        }

        let process_id_field = contents[..open_paren].trim();
        let comm = contents[open_paren + 1..close_paren].to_owned();
        let trailing = contents[close_paren + 1..].trim();
        let mut parts = trailing.split_whitespace();
        let state = parts
            .next()
            .and_then(|value| value.chars().next())
            .ok_or_else(|| Self::invalid_data(pid, path, "stat missing process state"))?;
        let parent_pid_field = parts
            .next()
            .ok_or_else(|| Self::invalid_data(pid, path, "stat missing parent pid"))?;

        // FR-P03's PID-wraparound safety depends on distinguishing a stale
        // cached process from a freshly reused numeric PID. `/proc/<pid>/stat`
        // field 22 (`starttime`) gives a stable kernel-assigned birth marker,
        // so the ancestry cache can reject an old chain as soon as the same
        // PID starts a different process instance.
        let start_time_ticks_field = parts
            .nth(17)
            .ok_or_else(|| Self::invalid_data(pid, path, "stat missing starttime field"))?;

        Ok(ProcStat {
            pid: Self::parse_u32_field(process_id_field, "pid")
                .map_err(|source| Self::classify_io(pid, path, source))?,
            comm,
            state,
            ppid: Self::parse_u32_field(parent_pid_field, "ppid")
                .map_err(|source| Self::classify_io(pid, path, source))?,
            start_time_ticks: start_time_ticks_field.parse().map_err(|source| {
                Self::classify_io(
                    pid,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("could not parse starttime as u64: {source}"),
                    ),
                )
            })?,
        })
    }

    fn parse_u32_field(value: &str, field_name: &str) -> io::Result<u32> {
        value.parse().map_err(|source| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("could not parse {field_name} as u32: {source}"),
            )
        })
    }

    fn parse_first_whitespace_u32(value: &str, field_name: &str) -> io::Result<u32> {
        let first = value.split_whitespace().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{field_name} field is empty"),
            )
        })?;
        Self::parse_u32_field(first, field_name)
    }

    fn invalid_data(pid: u32, path: &Path, reason: &str) -> ProcReadError {
        Self::classify_io(
            pid,
            path,
            io::Error::new(io::ErrorKind::InvalidData, reason.to_owned()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcReadError, ProcReader};
    use std::{
        fs,
        io::{self, Write},
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
        process::Command,
        sync::{Arc, Mutex},
    };
    use tempfile::TempDir;
    use tracing::subscriber::with_default;
    use tracing_subscriber::fmt::MakeWriter;

    #[test]
    fn proc_reader_reads_status_fields_from_proc_fixture() {
        let fixture = ProcFixture::new();
        fixture.write_mounts("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
        fixture.write_status(
            4242,
            "Name:\tfixture-proc\nTgid:\t4242\nPPid:\t11\nUid:\t1000\t1000\t1000\t1000\n",
        );

        let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
        let status = reader.read_status(4242).expect("status is parsed");

        assert_eq!(status.name, "fixture-proc");
        assert_eq!(status.tgid, 4242);
        assert_eq!(status.ppid, 11);
        assert_eq!(status.uid, 1000);
    }

    #[test]
    fn proc_reader_resolves_host_visible_exe_symlink() {
        let fixture = ProcFixture::new();
        fixture.write_mounts("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
        fixture.write_exe_link(17, "/var/lib/docker/overlay2/merged/usr/bin/sleep");

        let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
        let exe = reader.read_exe(17).expect("exe symlink resolves");

        assert_eq!(
            exe,
            Path::new("/var/lib/docker/overlay2/merged/usr/bin/sleep")
        );
    }

    #[test]
    fn proc_reader_preserves_full_cgroup_hierarchy_text() {
        let fixture = ProcFixture::new();
        fixture.write_mounts("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
        let cgroup = "0::/system.slice/docker-123.scope\n1:name=systemd:/user.slice/user-1000.slice/session-1.scope\n";
        fixture.write_cgroup(7, cgroup);

        let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
        let observed = reader.read_cgroup(7).expect("cgroup text is read");

        assert_eq!(observed, cgroup);
    }

    #[test]
    fn proc_reader_parses_stat_with_spaces_in_comm() {
        let fixture = ProcFixture::new();
        fixture.write_mounts("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
        fixture.write_stat(99, "99 (sleep worker) S 12 99 99 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1234 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");

        let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
        let stat = reader.read_stat(99).expect("stat is parsed");

        assert_eq!(stat.pid, 99);
        assert_eq!(stat.comm, "sleep worker");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.ppid, 12);
        assert_eq!(stat.start_time_ticks, 1234);
    }

    #[test]
    fn proc_reader_maps_real_exited_process_race_to_not_found() {
        let reader = ProcReader::new().expect("/proc is available");
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("short-lived helper launches");
        let pid = child.id();
        let status = child.wait().expect("short-lived helper exits");
        assert!(status.success());

        let error = reader
            .read_status(pid)
            .expect_err("exited process should map to NotFound");
        assert!(matches!(error, ProcReadError::NotFound { pid: observed, .. } if observed == pid));
    }

    #[test]
    fn proc_reader_maps_permission_denied_to_permission_error() {
        let fixture = ProcFixture::new();
        fixture.write_mounts("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
        let status_path = fixture.write_status(
            88,
            "Name:\tsecret\nTgid:\t88\nPPid:\t1\nUid:\t1001\t1001\t1001\t1001\n",
        );
        let original = fs::metadata(&status_path)
            .expect("status fixture exists")
            .permissions();
        let mut locked = original.clone();
        locked.set_mode(0o0);
        fs::set_permissions(&status_path, locked).expect("fixture can remove read perms");

        let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
        let error = reader
            .read_status(88)
            .expect_err("permission denied should map cleanly");

        fs::set_permissions(&status_path, original).expect("fixture permissions restored");
        assert!(matches!(error, ProcReadError::Permission { pid, .. } if pid == 88));
    }

    #[test]
    fn proc_reader_logs_single_hidepid_warning_at_startup() {
        let fixture = ProcFixture::new();
        fixture.write_mounts(
            "proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2,gid=777 0 0\n",
        );
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(TestWriterFactory {
                buffer: Arc::clone(&buffer),
            })
            .finish();

        with_default(subscriber, || {
            let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
            assert_eq!(reader.hidepid_setting().mode, 2);
            assert_eq!(reader.hidepid_setting().gid, Some(777));
        });

        let logs = String::from_utf8(buffer.lock().expect("buffer lock").clone())
            .expect("captured logs are utf-8");
        let occurrences = logs.matches("proc_hidepid_detected").count();
        assert_eq!(
            occurrences, 1,
            "expected exactly one startup warning: {logs}"
        );
        assert!(
            logs.contains("hidepid=2"),
            "warning should name active mode: {logs}"
        );
    }

    #[derive(Clone)]
    struct TestWriterFactory {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> MakeWriter<'a> for TestWriterFactory {
        type Writer = TestWriter;

        fn make_writer(&'a self) -> Self::Writer {
            TestWriter {
                buffer: Arc::clone(&self.buffer),
            }
        }
    }

    struct TestWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .expect("log capture buffer lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ProcFixture {
        tempdir: TempDir,
    }

    impl ProcFixture {
        fn new() -> Self {
            Self {
                tempdir: tempfile::tempdir().expect("temporary proc fixture root exists"),
            }
        }

        fn root(&self) -> &Path {
            self.tempdir.path()
        }

        fn write_mounts(&self, contents: &str) {
            fs::write(self.root().join("mounts"), contents).expect("mounts fixture is written");
        }

        fn write_status(&self, pid: u32, contents: &str) -> std::path::PathBuf {
            let path = self.proc_file(pid, "status");
            fs::write(&path, contents).expect("status fixture is written");
            path
        }

        fn write_cgroup(&self, pid: u32, contents: &str) {
            let path = self.proc_file(pid, "cgroup");
            fs::write(path, contents).expect("cgroup fixture is written");
        }

        fn write_stat(&self, pid: u32, contents: &str) {
            let path = self.proc_file(pid, "stat");
            fs::write(path, contents).expect("stat fixture is written");
        }

        fn write_exe_link(&self, pid: u32, target: &str) {
            let path = self.proc_file(pid, "exe");
            symlink(target, path).expect("exe symlink fixture is created");
        }

        fn proc_file(&self, pid: u32, name: &str) -> std::path::PathBuf {
            let pid_dir = self.root().join(pid.to_string());
            fs::create_dir_all(&pid_dir).expect("pid fixture directory exists");
            pid_dir.join(name)
        }
    }
}
