//! Writes that cannot leave a live key, or a half-written file, behind.
//!
//! Two shapes, because the two writers differ in who owns the write. We own the bytes of a
//! document, so it is staged as a file and renamed. `eth_keystore::encrypt_key` owns the
//! write of a vault — its whole public surface is path-based, one `File::create` straight
//! to the destination — so the directory it writes into is the only handle there is on it,
//! and the way to make that write atomic is to give it a temporary directory to write into
//! and rename the result out.

use std::io;
use std::path::{Path, PathBuf};

/// Prefix of the randomly-named file a document write stages under. Random so two
/// processes replacing the same document cannot collide on one staging path, prefixed so a
/// copy a SIGKILL leaves behind is still recognisably ours rather than unexplained.
pub const DOC_STAGE_PREFIX: &str = ".ks-stage-";

/// Set a path's mode. No-op off unix, where the enclosing directory ACL is the control.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// Clear a directory's group and other bits, keeping the owner's. Tightens 0755 to 0700
/// the way a plain `set_mode(0o700)` did, but never LOOSENS: a directory an operator locked
/// down to 0500 stays at 0500, and the write that needed it refuses instead of quietly
/// reopening it.
pub fn tighten_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o700;
        set_mode(path, mode)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Best-effort. A failed directory fsync cannot make a rename non-atomic — only
/// non-durable across a power cut, which this module does not promise.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        let _ = std::fs::File::open(dir).and_then(|f| f.sync_all());
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// A staging directory for a write we do not perform ourselves.
///
/// Named after what it holds rather than randomly, so a copy a SIGKILL leaves behind is
/// nameable — and therefore classifiable and deletable, which is the property that made the
/// group half's leftover recoverable. Removed on every exit this process can take: `?`,
/// early return, panic, unwind. The scan covers the one it cannot.
pub struct Stage(PathBuf);

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Stage {
    /// Fresh, empty and 0700, replacing any leftover of the same name.
    pub fn create(path: PathBuf) -> io::Result<Self> {
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        // DirBuilder::mode is masked by the umask, so the mode is set here, not requested.
        set_mode(&path, 0o700)?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Put `bytes` in the stage at `name`, 0600 from creation and synced. For a library
    /// whose only input is a PATH: the stage is the sole handle on where that path lands.
    pub fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        use std::io::Write;
        let path = self.0.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true); // O_EXCL: never adopt an existing path
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(path)
    }

    /// Move `name` out to `dest`. Restricted and synced while still inside the 0700 stage,
    /// so the file is never briefly world-readable at its real path, and the bytes are down
    /// before the rename that publishes them.
    pub fn promote(&self, name: &str, dest: &Path) -> io::Result<()> {
        let staged = self.0.join(name);
        set_mode(&staged, 0o600)?;
        std::fs::OpenOptions::new().write(true).open(&staged)?.sync_all()?;
        std::fs::rename(&staged, dest)?;
        if let Some(parent) = dest.parent() {
            sync_dir(parent);
        }
        Ok(())
    }
}

/// Replace `dest` with `bytes`: staged in `root` at 0600 from creation, synced, renamed.
/// A crash can leave the staged copy — which the scan reports — but never a truncated
/// destination, and never a destination that was briefly readable by anyone else.
pub fn write_doc(root: &Path, dest: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = tempfile::Builder::new().prefix(DOC_STAGE_PREFIX).tempfile_in(root)?;
    f.write_all(bytes)?;
    // The rename is only atomic with respect to a crash if the bytes are down first.
    f.as_file().sync_all()?;
    f.persist(dest).map_err(|e| e.error)?;
    sync_dir(root);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stage_is_removed_on_every_exit_this_process_can_take() {
        // The three ways `change_password` leaked a live account key: an early return past
        // the cleanup, a panic, and a normal exit that simply never reached it.
        let dir = tempfile::tempdir().unwrap();

        let early = || -> io::Result<()> {
            let stage = Stage::create(dir.path().join(".stage-early"))?;
            std::fs::write(stage.path().join("k.json"), "ciphertext")?;
            Err(io::Error::other("ENOSPC"))
        };
        assert!(early().is_err());
        assert!(!dir.path().join(".stage-early").exists(), "an early return left a key staged");

        let hit = std::panic::catch_unwind(|| {
            let stage = Stage::create(dir.path().join(".stage-panic")).unwrap();
            std::fs::write(stage.path().join("k.json"), "ciphertext").unwrap();
            panic!("ENOSPC");
        });
        assert!(hit.is_err());
        assert!(!dir.path().join(".stage-panic").exists(), "a panic left a key staged");

        {
            let stage = Stage::create(dir.path().join(".stage-ok")).unwrap();
            std::fs::write(stage.path().join("k.json"), "ciphertext").unwrap();
            stage.promote("k.json", &dir.path().join("k.json")).unwrap();
        }
        assert!(!dir.path().join(".stage-ok").exists());
        assert_eq!(std::fs::read_to_string(dir.path().join("k.json")).unwrap(), "ciphertext");
    }

    #[test]
    fn a_blocked_promotion_leaves_nothing_staged() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("blocked.json");
        std::fs::create_dir_all(&dest).unwrap();

        let stage = Stage::create(dir.path().join(".stage-blocked")).unwrap();
        std::fs::write(stage.path().join("k.json"), "ciphertext").unwrap();
        assert!(stage.promote("k.json", &dest).is_err());
        let path = stage.path().to_path_buf();
        drop(stage);
        assert!(!path.exists(), "a decryptable key outlived a failed rename");
    }

    #[test]
    fn a_staged_file_is_restricted_before_it_is_published() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let stage = Stage::create(dir.path().join(".stage-mode")).unwrap();
            assert_eq!(std::fs::metadata(stage.path()).unwrap().permissions().mode() & 0o777, 0o700);
            std::fs::write(stage.path().join("k.json"), "ciphertext").unwrap();
            set_mode(&stage.path().join("k.json"), 0o644).unwrap();
            let dest = dir.path().join("k.json");
            stage.promote("k.json", &dest).unwrap();
            assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_document_is_never_written_in_place_and_never_briefly_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("doc.json");
        write_doc(dir.path(), &dest, b"{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "{\"a\":1}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // A failed write leaves the destination byte-identical and nothing staged. The
        // staging name is random, so this blocks the write the only way that covers EVERY
        // name: the directory itself.
        set_mode(dir.path(), 0o500).unwrap();
        let failed = write_doc(dir.path(), &dest, b"{\"a\":2}");
        set_mode(dir.path(), 0o700).unwrap();
        assert!(failed.is_err(), "a failed staging must not report success");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "{\"a\":1}");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "doc.json")
            .collect();
        assert!(left.is_empty(), "left staged: {left:?}");
    }

    #[test]
    fn two_writers_do_not_collide_on_one_staging_path() {
        // The fixed `groups.json.tmp` was a single path two processes both created. A
        // random name removes the collision outright rather than serialising around it.
        let dir = tempfile::tempdir().unwrap();
        let mut names = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let f = tempfile::Builder::new().prefix(DOC_STAGE_PREFIX).tempfile_in(dir.path()).unwrap();
            names.insert(f.path().file_name().unwrap().to_string_lossy().into_owned());
            std::mem::forget(f);
        }
        assert_eq!(names.len(), 8, "staging names collided: {names:?}");
        assert!(names.iter().all(|n| n.starts_with(DOC_STAGE_PREFIX)));
    }
}
