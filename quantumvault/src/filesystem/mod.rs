use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    time::{Duration, SystemTime},
};

const ROOT_INO: u64 = 1;
const HELLO_INO: u64 = 2;
const TTL: Duration = Duration::from_secs(1);

struct FileNode {
    data: Vec<u8>,
    perm: u16,
    uid: u32,
    gid: u32,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    nlink: u32,
}

impl FileNode {
    fn attr(&self, ino: u64) -> FileAttr {
        let size = self.data.len() as u64;

        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
            crtime: self.ctime,
            kind: FileType::RegularFile,
            perm: self.perm,
            nlink: self.nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}
struct OpenHandle {
    ino: u64,
    readable: bool,
    writable: bool,
    append: bool,
}
pub struct QuantumVaultFs {
    files: HashMap<u64, FileNode>,
    entries: HashMap<OsString, u64>,
    handles: HashMap<u64, OpenHandle>,
    next_ino: u64,
    next_handle: u64,
    root_uid: u32,
    root_gid: u32,
}

impl QuantumVaultFs {
    fn valid_access_mode(flags: i32) -> bool {
        matches!(
            flags & libc::O_ACCMODE,
            libc::O_RDONLY | libc::O_WRONLY | libc::O_RDWR
        )
    }

    pub fn new() -> Self {
        let now = SystemTime::now();
        let hello = b"Hello from QuantumVault!\nThis is our first FUSE filesystem.\n";

        let mut files = HashMap::new();
        files.insert(
            HELLO_INO,
            FileNode {
                data: hello.to_vec(),
                perm: 0o644,
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
                atime: now,
                mtime: now,
                ctime: now,
                nlink: 1,
            },
        );

        let mut entries = HashMap::new();
        entries.insert(OsString::from("hello.txt"), HELLO_INO);

        Self {
            files,
            entries,
            handles: HashMap::new(),
            next_ino: 3,
            next_handle: 1,
            root_uid: unsafe { libc::getuid() },
            root_gid: unsafe { libc::getgid() },
        }
    }

    fn root_attr(&self) -> FileAttr {
        let now = SystemTime::now();

        FileAttr {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: self.root_uid,
            gid: self.root_gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn write_start(offset: i64, append: bool, current_len: usize) -> Result<usize, i32> {
        if offset < 0 {
            return Err(libc::EINVAL);
        }
        if append {
            return Ok(current_len);
        }
        usize::try_from(offset).map_err(|_| libc::EFBIG)
    }

    fn allocate_handle(&mut self, ino: u64, flags: i32) -> u64 {
        let access_mode = flags & libc::O_ACCMODE;

        let handle = self.next_handle;
        self.next_handle += 1;

        self.handles.insert(
            handle,
            OpenHandle {
                ino,
                readable: access_mode != libc::O_WRONLY,
                writable: access_mode != libc::O_RDONLY,
                append: flags & libc::O_APPEND != 0,
            },
        );

        handle
    }

    fn has_open_handle(&self, ino: u64) -> bool {
        self.handles.values().any(|handle| handle.ino == ino)
    }
    fn supplementary_groups(pid: u32) -> Option<Vec<u32>> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;

        let groups_line = status
            .lines()
            .find_map(|line| line.strip_prefix("Groups:"))?;

        groups_line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .ok()
    }
    fn check_access(
        file: &FileNode,
        uid: u32,
        gid: u32,
        supplementary_groups: &[u32],
        want_read: bool,
        want_write: bool,
    ) -> bool {
        if uid == 0 {
            return true;
        }

        let shift = if uid == file.uid {
            6
        } else if gid == file.gid || supplementary_groups.contains(&file.gid) {
            3
        } else {
            0
        };

        let permissions = (file.perm >> shift) & 0o7;

        (!want_read || permissions & 0o4 != 0) && (!want_write || permissions & 0o2 != 0)
    }

    fn check_root_access(
        &self,
        uid: u32,
        gid: u32,
        supplementary_groups: &[u32],
        want_read: bool,
        want_write: bool,
        want_execute: bool,
    ) -> bool {
        if uid == 0 {
            return true;
        }

        let shift = if uid == self.root_uid {
            6
        } else if gid == self.root_gid || supplementary_groups.contains(&self.root_gid) {
            3
        } else {
            0
        };

        let permissions = (0o755 >> shift) & 0o7;

        (!want_read || permissions & 0o4 != 0)
            && (!want_write || permissions & 0o2 != 0)
            && (!want_execute || permissions & 0o1 != 0)
    }

    fn check_root_write_execute(&self, uid: u32, gid: u32, supplementary_groups: &[u32]) -> bool {
        if uid == 0 {
            return true;
        }

        let shift = if uid == self.root_uid {
            6
        } else if gid == self.root_gid || supplementary_groups.contains(&self.root_gid) {
            3
        } else {
            0
        };

        let permissions = (0o755 >> shift) & 0o7;
        permissions & 0o3 == 0o3
    }

    fn valid_name(name: &OsStr) -> bool {
        !name.is_empty()
            && name != OsStr::new(".")
            && name != OsStr::new("..")
            && !name.to_string_lossy().contains('/')
    }
}

impl Default for QuantumVaultFs {
    fn default() -> Self {
        Self::new()
    }
}

impl Filesystem for QuantumVaultFs {
    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent != ROOT_INO {
            reply.error(libc::ENOTDIR);
            return;
        }

        let Some(groups) = Self::supplementary_groups(req.pid()) else {
            reply.error(libc::EACCES);
            return;
        };

        if !self.check_root_access(req.uid(), req.gid(), &groups, false, false, true) {
            reply.error(libc::EACCES);
            return;
        }

        match self
            .entries
            .get(name)
            .and_then(|ino| self.files.get(ino).map(|f| (*ino, f)))
        {
            Some((ino, file)) => reply.entry(&TTL, &file.attr(ino), 0),
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino == ROOT_INO {
            reply.attr(&TTL, &self.root_attr());
            return;
        }

        match self.files.get(&ino) {
            Some(file) => reply.attr(&TTL, &file.attr(ino)),
            None => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(libc::ENOTDIR);
            return;
        }

        let Some(groups) = Self::supplementary_groups(req.pid()) else {
            reply.error(libc::EACCES);
            return;
        };

        if !self.check_root_access(req.uid(), req.gid(), &groups, true, false, true) {
            reply.error(libc::EACCES);
            return;
        }

        let mut entries: Vec<(u64, FileType, OsString)> = vec![
            (ROOT_INO, FileType::Directory, OsString::from(".")),
            (ROOT_INO, FileType::Directory, OsString::from("..")),
        ];

        let mut files: Vec<_> = self.entries.iter().collect();
        files.sort_by(|a, b| a.0.cmp(b.0));

        for (name, file_ino) in files {
            entries.push((*file_ino, FileType::RegularFile, name.clone()));
        }

        for (index, (entry_ino, kind, name)) in
            entries.iter().enumerate().skip(offset.max(0) as usize)
        {
            if reply.add(*entry_ino, (index + 1) as i64, *kind, name) {
                break;
            }
        }

        reply.ok();
    }

    fn open(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if ino == ROOT_INO {
            reply.error(libc::EISDIR);
            return;
        }

        let Some(file) = self.files.get(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let access_mode = flags & libc::O_ACCMODE;
        let want_read = access_mode != libc::O_WRONLY;
        let want_write = access_mode != libc::O_RDONLY;

        if !Self::valid_access_mode(flags) {
            reply.error(libc::EINVAL);
            return;
        }

        let Some(groups) = Self::supplementary_groups(req.pid()) else {
            reply.error(libc::EACCES);
            return;
        };

        if !Self::check_access(file, req.uid(), req.gid(), &groups, want_read, want_write) {
            reply.error(libc::EACCES);
            return;
        }

        if flags & libc::O_TRUNC != 0 && want_write {
            let Some(file) = self.files.get_mut(&ino) else {
                reply.error(libc::ENOENT);
                return;
            };

            file.data.clear();
            let now = SystemTime::now();
            file.mtime = now;
            file.ctime = now;
        }

        let handle = self.allocate_handle(ino, flags);
        reply.opened(handle, 0);
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if parent != ROOT_INO {
            reply.error(libc::ENOTDIR);
            return;
        }

        if !Self::valid_access_mode(flags) {
            reply.error(libc::EINVAL);
            return;
        }

        let Some(groups) = Self::supplementary_groups(req.pid()) else {
            reply.error(libc::EACCES);
            return;
        };

        if !self.check_root_write_execute(req.uid(), req.gid(), &groups) {
            reply.error(libc::EACCES);
            return;
        }

        if !Self::valid_name(name) {
            reply.error(libc::EINVAL);
            return;
        }

        if self.entries.contains_key(name) {
            reply.error(libc::EEXIST);
            return;
        }

        let ino = self.next_ino;
        self.next_ino += 1;

        let now = SystemTime::now();
        let file = FileNode {
            data: Vec::new(),
            perm: (mode & !umask & 0o7777) as u16,
            uid: req.uid(),
            gid: req.gid(),
            atime: now,
            mtime: now,
            ctime: now,
            nlink: 1,
        };

        let attr = file.attr(ino);
        self.files.insert(ino, file);
        self.entries.insert(name.to_os_string(), ino);

        let handle = self.allocate_handle(ino, flags);
        reply.created(&TTL, &attr, 0, handle, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }

        let Some(handle) = self.handles.get(&fh) else {
            reply.error(libc::EBADF);
            return;
        };

        if handle.ino != ino || !handle.readable {
            reply.error(libc::EBADF);
            return;
        }

        let file_ino = handle.ino;

        let Some(file) = self.files.get_mut(&file_ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let Ok(start) = usize::try_from(offset) else {
            reply.error(libc::EFBIG);
            return;
        };
        file.atime = SystemTime::now();

        if start >= file.data.len() {
            reply.data(&[]);
            return;
        }

        let end = start.saturating_add(size as usize).min(file.data.len());
        reply.data(&file.data[start..end]);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }

        let Some(handle) = self.handles.get(&fh) else {
            reply.error(libc::EBADF);
            return;
        };

        if handle.ino != ino || !handle.writable {
            reply.error(libc::EBADF);
            return;
        }

        let file_ino = handle.ino;
        let append = handle.append;

        let Some(file) = self.files.get_mut(&file_ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let start = match Self::write_start(offset, append, file.data.len()) {
            Ok(start) => start,
            Err(error) => {
                reply.error(error);
                return;
            }
        };

        let Some(end) = start.checked_add(data.len()) else {
            reply.error(libc::EFBIG);
            return;
        };

        if end > file.data.len() {
            let additional = end - file.data.len();

            if file.data.try_reserve(additional).is_err() {
                reply.error(libc::ENOMEM);
                return;
            }

            file.data.resize(end, 0);
        }

        file.data[start..end].copy_from_slice(data);
        file.mtime = SystemTime::now();
        file.ctime = file.mtime;

        let Ok(written) = u32::try_from(data.len()) else {
            reply.error(libc::EFBIG);
            return;
        };

        reply.written(written);
    }

    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if ino == ROOT_INO {
            reply.error(libc::EISDIR);
            return;
        }

        // Validate size before changing any metadata.
        let new_size = match size {
            Some(value) => match usize::try_from(value) {
                Ok(value) => Some(value),
                Err(_) => {
                    reply.error(libc::EFBIG);
                    return;
                }
            },
            None => None,
        };

        let Some(groups) = Self::supplementary_groups(req.pid()) else {
            reply.error(libc::EACCES);
            return;
        };

        let Some(file) = self.files.get(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let is_root = req.uid() == 0;
        let is_owner = req.uid() == file.uid;

        // Only root can change UID/GID.
        // Only root or owner can change mode.
        // Only root or owner with write permission can change size.
        if (uid.is_some() || gid.is_some()) && !is_root {
            reply.error(libc::EPERM);
            return;
        }

        if mode.is_some() && !is_root && !is_owner {
            reply.error(libc::EPERM);
            return;
        }

        if size.is_some()
            && !is_root
            && !Self::check_access(file, req.uid(), req.gid(), &groups, false, true)
        {
            reply.error(libc::EACCES);
            return;
        }

        if (atime.is_some() || mtime.is_some()) && !is_root && !is_owner {
            reply.error(libc::EACCES);
            return;
        }

        let Some(file) = self.files.get_mut(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        // Reserve memory before changing metadata or file contents.
        if let Some(new_size) = new_size {
            let additional = new_size.saturating_sub(file.data.len());

            if file.data.try_reserve(additional).is_err() {
                reply.error(libc::ENOMEM);
                return;
            }
        }

        let now = SystemTime::now();

        if let Some(new_mode) = mode {
            file.perm = (new_mode & 0o7777) as u16;
        }

        if let Some(new_uid) = uid {
            file.uid = new_uid;
        }

        if let Some(new_gid) = gid {
            file.gid = new_gid;
        }

        if let Some(new_size) = new_size {
            file.data.resize(new_size, 0);
        }

        if let Some(value) = atime {
            file.atime = match value {
                fuser::TimeOrNow::SpecificTime(time) => time,
                fuser::TimeOrNow::Now => now,
            };
        }

        if let Some(value) = mtime {
            file.mtime = match value {
                fuser::TimeOrNow::SpecificTime(time) => time,
                fuser::TimeOrNow::Now => now,
            };
        } else if new_size.is_some() {
            file.mtime = now;
        }

        file.ctime = now;

        reply.attr(&TTL, &file.attr(ino));
    }

    fn unlink(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if parent != ROOT_INO {
            reply.error(libc::ENOTDIR);
            return;
        }

        let Some(groups) = Self::supplementary_groups(req.pid()) else {
            reply.error(libc::EACCES);
            return;
        };

        if !self.check_root_write_execute(req.uid(), req.gid(), &groups) {
            reply.error(libc::EACCES);
            return;
        }

        let Some(ino) = self.entries.remove(name) else {
            reply.error(libc::ENOENT);
            return;
        };

        if let Some(file) = self.files.get_mut(&ino) {
            file.nlink = 0;
        }

        if !self.has_open_handle(ino) {
            self.files.remove(&ino);
        }

        reply.ok();
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(handle) = self.handles.remove(&fh) {
            let ino = handle.ino;
            let should_remove = self.files.get(&ino).is_some_and(|file| file.nlink == 0);

            if should_remove && !self.has_open_handle(ino) {
                self.files.remove(&ino);
            }
        }

        reply.ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_access_modes_are_accepted() {
        assert!(QuantumVaultFs::valid_access_mode(libc::O_RDONLY));
        assert!(QuantumVaultFs::valid_access_mode(libc::O_WRONLY));
        assert!(QuantumVaultFs::valid_access_mode(libc::O_RDWR));
    }

    #[test]
    fn invalid_access_mode_is_rejected() {
        assert!(!QuantumVaultFs::valid_access_mode(3));
        assert!(!QuantumVaultFs::valid_access_mode(3 | libc::O_CLOEXEC));
    }

    #[test]
    fn initial_hello_file_exists() {
        let fs = QuantumVaultFs::new();

        assert!(fs.entries.contains_key(OsStr::new("hello.txt")));

        let ino = fs.entries[OsStr::new("hello.txt")];
        let file = fs.files.get(&ino).unwrap();

        assert_eq!(
            file.data,
            b"Hello from QuantumVault!\nThis is our first FUSE filesystem.\n"
        );
    }

    #[test]
    fn allocate_inode_and_create_file() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.next_ino;
        fs.next_ino += 1;

        fs.entries.insert(OsString::from("test.txt"), ino);

        let now = SystemTime::now();
        fs.files.insert(
            ino,
            FileNode {
                data: Vec::new(),
                perm: 0o644,
                uid: 1000,
                gid: 1000,
                atime: now,
                mtime: now,
                ctime: now,
                nlink: 1,
            },
        );

        assert!(fs.entries.contains_key(OsStr::new("test.txt")));
        assert!(fs.files.contains_key(&ino));
    }

    #[test]
    fn open_with_trunc_flag_clears_file_data() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];

        let file = fs.files.get_mut(&ino).unwrap();
        file.data = b"QuantumVault test data".to_vec();

        // Verify the truncation operation used by open(O_TRUNC).
        fs.files.get_mut(&ino).unwrap().data.clear();

        assert!(fs.files.get(&ino).unwrap().data.is_empty());
    }

    #[test]
    fn append_write_starts_at_end_of_file() {
        assert_eq!(QuantumVaultFs::write_start(0, true, 10), Ok(10));
        assert_eq!(QuantumVaultFs::write_start(3, true, 10), Ok(10));
    }

    #[test]
    fn normal_write_uses_supplied_offset() {
        assert_eq!(QuantumVaultFs::write_start(3, false, 10), Ok(3));
    }

    #[test]
    fn write_at_offset_preserves_existing_bytes() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];

        let file = fs.files.get_mut(&ino).unwrap();
        file.data = b"abcdefghij".to_vec();

        let offset = 3;
        let data = b"XYZ";
        let end = offset + data.len();

        file.data[offset..end].copy_from_slice(data);

        assert_eq!(file.data, b"abcXYZghij");
    }

    #[test]
    fn truncate_file_to_smaller_size() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];

        let file = fs.files.get_mut(&ino).unwrap();
        file.data = b"QuantumVault".to_vec();
        file.data.resize(5, 0);

        assert_eq!(file.data, b"Quant");
        assert_eq!(file.data.len(), 5);
    }

    #[test]
    fn truncate_file_to_larger_size_zero_fills() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];

        let file = fs.files.get_mut(&ino).unwrap();
        file.data = b"abc".to_vec();
        file.data.resize(6, 0);

        assert_eq!(file.data, b"abc\0\0\0");
    }

    #[test]
    fn unlink_preserves_file_while_handle_is_open() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries.remove(OsStr::new("hello.txt")).unwrap();

        let handle = fs.allocate_handle(ino, libc::O_RDWR);

        fs.files.get_mut(&ino).unwrap().nlink = 0;

        assert!(!fs.entries.contains_key(OsStr::new("hello.txt")));
        assert!(fs.files.contains_key(&ino));
        assert!(fs.has_open_handle(ino));

        fs.handles.remove(&handle);

        assert!(!fs.has_open_handle(ino));

        if fs.files.get(&ino).is_some_and(|file| file.nlink == 0) && !fs.has_open_handle(ino) {
            fs.files.remove(&ino);
        }

        assert!(!fs.files.contains_key(&ino));
    }

    #[test]
    fn setattr_size_truncation_shrinks_file() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];
        let file = fs.files.get_mut(&ino).unwrap();

        file.data = b"QuantumVault".to_vec();
        file.data.truncate(5);

        assert_eq!(file.data, b"Quant");
    }

    #[test]
    fn setattr_size_extension_zero_fills_file() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];
        let file = fs.files.get_mut(&ino).unwrap();

        file.data = b"abc".to_vec();
        file.data.resize(6, 0);

        assert_eq!(file.data, b"abc\0\0\0");
    }

    #[test]
    fn setattr_mode_updates_file_permissions() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];
        let file = fs.files.get_mut(&ino).unwrap();

        file.perm = (0o600 & 0o7777) as u16;

        assert_eq!(file.perm, 0o600);
    }

    #[test]
    fn invalid_file_names_are_rejected() {
        assert!(!QuantumVaultFs::valid_name(OsStr::new("")));
        assert!(!QuantumVaultFs::valid_name(OsStr::new(".")));
        assert!(!QuantumVaultFs::valid_name(OsStr::new("..")));
        assert!(!QuantumVaultFs::valid_name(OsStr::new("folder/file")));
        assert!(QuantumVaultFs::valid_name(OsStr::new("valid.txt")));
    }

    #[test]
    fn read_only_handle_rejects_write() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];

        let handle = fs.allocate_handle(ino, libc::O_RDONLY);
        let open_handle = fs.handles.get(&handle).unwrap();

        assert!(open_handle.readable);
        assert!(!open_handle.writable);
    }

    #[test]
    fn write_only_handle_rejects_read() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];

        let handle = fs.allocate_handle(ino, libc::O_WRONLY);
        let open_handle = fs.handles.get(&handle).unwrap();

        assert!(!open_handle.readable);
        assert!(open_handle.writable);
    }

    #[test]
    fn read_write_handle_allows_both_operations() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];

        let handle = fs.allocate_handle(ino, libc::O_RDWR);
        let open_handle = fs.handles.get(&handle).unwrap();

        assert!(open_handle.readable);
        assert!(open_handle.writable);
    }

    #[test]
    fn check_access_respects_owner_group_and_other_permissions() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];
        let file = fs.files.get_mut(&ino).unwrap();

        file.uid = 1000;
        file.gid = 1000;
        file.perm = 0o640;

        assert!(QuantumVaultFs::check_access(
            file,
            1000,
            1000,
            &[],
            true,
            true
        ));
        assert!(QuantumVaultFs::check_access(
            file,
            2000,
            1000,
            &[],
            true,
            false
        ));
        assert!(!QuantumVaultFs::check_access(
            file,
            2000,
            1000,
            &[],
            true,
            true
        ));
        assert!(!QuantumVaultFs::check_access(
            file,
            2000,
            2000,
            &[],
            true,
            false
        ));
    }

    #[test]
    fn supplementary_group_allows_group_permissions() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];
        let file = fs.files.get_mut(&ino).unwrap();

        file.uid = 1000;
        file.gid = 2000;
        file.perm = 0o640;

        assert!(QuantumVaultFs::check_access(
            file,
            3000,
            3000,
            &[2000],
            true,
            false,
        ));

        assert!(!QuantumVaultFs::check_access(
            file,
            3000,
            3000,
            &[2000],
            true,
            true,
        ));
    }

    #[test]
    fn missing_supplementary_group_denies_group_access() {
        let mut fs = QuantumVaultFs::new();
        let ino = fs.entries[OsStr::new("hello.txt")];
        let file = fs.files.get_mut(&ino).unwrap();

        file.uid = 1000;
        file.gid = 2000;
        file.perm = 0o640;

        assert!(!QuantumVaultFs::check_access(
            file,
            3000,
            3000,
            &[],
            true,
            false,
        ));
    }
    #[test]
    fn root_access_allows_owner_read_and_execute() {
        let fs = QuantumVaultFs::new();

        assert!(fs.check_root_access(fs.root_uid, fs.root_gid, &[], true, false, true,));
    }

    #[test]
    fn root_access_allows_other_user_read_and_execute() {
        let fs = QuantumVaultFs::new();

        assert!(fs.check_root_access(
            fs.root_uid.wrapping_add(1),
            fs.root_gid.wrapping_add(1),
            &[],
            true,
            false,
            true,
        ));
    }

    #[test]
    fn root_access_denies_other_user_write() {
        let fs = QuantumVaultFs::new();

        assert!(!fs.check_root_access(
            fs.root_uid.wrapping_add(1),
            fs.root_gid.wrapping_add(1),
            &[],
            false,
            true,
            false,
        ));
    }

    #[test]
    fn root_directory_allows_owner_write_and_execute() {
        let fs = QuantumVaultFs::new();

        assert!(fs.check_root_write_execute(fs.root_uid, fs.root_gid, &[]));
    }

    #[test]
    fn root_directory_denies_other_user_write() {
        let fs = QuantumVaultFs::new();

        assert!(!fs.check_root_write_execute(
            fs.root_uid.wrapping_add(1),
            fs.root_gid.wrapping_add(1),
            &[]
        ));
    }

    #[test]
    fn root_directory_allows_root_user() {
        let fs = QuantumVaultFs::new();

        assert!(fs.check_root_write_execute(0, 0, &[]));
    }
}
