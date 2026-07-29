//! Standard-library Resource streaming and disk-delivery types.

use std::fs::{self, File, OpenOptions};
#[cfg(test)]
use std::io::Read;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rns_core::constants::RESOURCE_AUTO_COMPRESS_MAX_SIZE;

static NEXT_PERSIST_TEMP: AtomicU64 = AtomicU64::new(1);
static NEXT_RECEIVE_TEMP: AtomicU64 = AtomicU64::new(1);

/// A node-local identifier for an outgoing streaming Resource transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceTransferId(pub u64);

/// Failure reported for the new streaming Resource API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceTransferError {
    Source(String),
    Storage(String),
    Protocol(String),
    Cancelled,
}

/// How independent incoming Resources are delivered to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceReceiveMode {
    /// Assemble the complete logical Resource in memory.
    Memory { max_bytes: u64 },
    /// Write verified segments to a managed temporary file.
    TemporaryFile {
        directory: PathBuf,
        max_bytes: Option<u64>,
    },
}

impl Default for ResourceReceiveMode {
    fn default() -> Self {
        Self::Memory {
            max_bytes: RESOURCE_AUTO_COMPRESS_MAX_SIZE as u64,
        }
    }
}

/// A received disk-backed Resource.
///
/// The temporary file is removed when this value is dropped unless ownership
/// is transferred with [`ReceivedResourceFile::persist`].
#[derive(Debug)]
pub struct ReceivedResourceFile {
    path: Option<PathBuf>,
    pub original_hash: [u8; 32],
    pub size: u64,
    pub metadata: Option<Vec<u8>>,
}

impl ReceivedResourceFile {
    pub(crate) fn new(
        path: PathBuf,
        original_hash: [u8; 32],
        size: u64,
        metadata: Option<Vec<u8>>,
    ) -> Self {
        Self {
            path: Some(path),
            original_hash,
            size,
            metadata,
        }
    }

    /// Path of the managed temporary file.
    pub fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("persisted resource has no path")
    }

    /// Persist this Resource at `destination`.
    ///
    /// The final name appears atomically. Cross-filesystem moves are staged in
    /// the destination directory before the final rename.
    pub fn persist(
        mut self,
        destination: impl AsRef<Path>,
        overwrite: bool,
    ) -> io::Result<PathBuf> {
        let destination = destination.as_ref();
        let source = self.path.as_ref().expect("persisted resource has no path");
        match rename_final(source, destination, overwrite) {
            Ok(()) => {
                self.path = None;
                sync_parent(destination)?;
                return Ok(destination.to_path_buf());
            }
            Err(error) if error.raw_os_error() != Some(libc::EXDEV) => return Err(error),
            Err(_) => {}
        }

        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let sequence = NEXT_PERSIST_TEMP.fetch_add(1, Ordering::Relaxed);
        let stage = parent.join(format!(
            ".rns-resource-{}-{}.tmp",
            std::process::id(),
            sequence
        ));
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)?;
        let copied = io::copy(&mut input, &mut output)?;
        if copied != self.size {
            let _ = fs::remove_file(&stage);
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "resource size changed",
            ));
        }
        output.flush()?;
        output.sync_all()?;
        drop(output);
        rename_final(&stage, destination, overwrite).inspect_err(|_| {
            let _ = fs::remove_file(&stage);
        })?;
        sync_parent(destination)?;
        fs::remove_file(source)?;
        self.path = None;
        Ok(destination.to_path_buf())
    }
}

#[cfg(target_os = "linux")]
fn rename_final(source: &Path, destination: &Path, overwrite: bool) -> io::Result<()> {
    if overwrite {
        return fs::rename(source, destination);
    }
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
    })?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_final(source: &Path, destination: &Path, overwrite: bool) -> io::Result<()> {
    if !overwrite && destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "resource destination already exists",
        ));
    }
    fs::rename(source, destination)
}

impl Drop for ReceivedResourceFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub(crate) fn create_receive_file(
    directory: &Path,
    original_hash: &[u8; 32],
) -> io::Result<(File, PathBuf)> {
    fs::create_dir_all(directory)?;
    for _ in 0..100 {
        let sequence = NEXT_RECEIVE_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            "rns-resource-{:02x}{:02x}{:02x}{:02x}-{}-{}.part",
            original_hash[0],
            original_hash[1],
            original_hash[2],
            original_hash[3],
            std::process::id(),
            sequence
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique Resource temporary file",
    ))
}

/// Read exactly `length` bytes and reject both early EOF and trailing data.
#[cfg(test)]
fn read_declared(mut reader: impl Read, length: u64) -> io::Result<Vec<u8>> {
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length does not fit usize"))?;
    let mut data = vec![0; length];
    reader.read_exact(&mut data)?;
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resource source exceeds declared length",
        ));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_file_is_deleted_on_drop_and_can_be_persisted() {
        let root = tempfile::tempdir().unwrap();
        let temporary = root.path().join("temporary");
        fs::write(&temporary, b"resource").unwrap();
        {
            let artifact = ReceivedResourceFile::new(temporary.clone(), [7; 32], 8, None);
            assert_eq!(artifact.path(), temporary);
        }
        assert!(!temporary.exists());

        fs::write(&temporary, b"resource").unwrap();
        let destination = root.path().join("saved");
        let artifact = ReceivedResourceFile::new(temporary.clone(), [7; 32], 8, None);
        artifact.persist(&destination, false).unwrap();
        assert_eq!(fs::read(destination).unwrap(), b"resource");
        assert!(!temporary.exists());
    }

    #[test]
    fn declared_reader_rejects_short_and_long_sources() {
        assert_eq!(read_declared(&b"abc"[..], 3).unwrap(), b"abc");
        assert_eq!(
            read_declared(&b"ab"[..], 3).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            read_declared(&b"abcd"[..], 3).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
