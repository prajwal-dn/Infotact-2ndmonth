use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    Request,
};
use std::{
    ffi::OsStr,
    time::{Duration, UNIX_EPOCH},
};

const ROOT_INO: u64 = 1;
const HELLO_INO: u64 = 2;

const HELLO_CONTENT: &[u8] = b"Hello from QuantumVault!\nThis is our first FUSE filesystem.\n";

pub struct QuantumVaultFs;

impl QuantumVaultFs {
    fn root_attr() -> FileAttr {
        FileAttr {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn hello_attr() -> FileAttr {
        FileAttr {
            ino: HELLO_INO,
            size: HELLO_CONTENT.len() as u64,
            blocks: 1,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

impl Filesystem for QuantumVaultFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INO && name == OsStr::new("hello.txt") {
            reply.entry(&Duration::from_secs(1), &Self::hello_attr(), 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match ino {
            ROOT_INO => {
                reply.attr(&Duration::from_secs(1), &Self::root_attr());
            }
            HELLO_INO => {
                reply.attr(&Duration::from_secs(1), &Self::hello_attr());
            }
            _ => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(libc::ENOENT);
            return;
        }

        let entries = [
            (ROOT_INO, FileType::Directory, "."),
            (ROOT_INO, FileType::Directory, ".."),
            (HELLO_INO, FileType::RegularFile, "hello.txt"),
        ];

        for (index, (entry_ino, kind, name)) in
            entries.iter().enumerate().skip(offset.max(0) as usize)
        {
            if reply.add(*entry_ino, (index + 1) as i64, *kind, name) {
                break;
            }
        }

        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        if ino == HELLO_INO {
            reply.opened(0, 0);
        } else {
            reply.error(libc::EISDIR);
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if ino != HELLO_INO {
            reply.error(libc::ENOENT);
            return;
        }

        let start = offset.max(0) as usize;

        if start >= HELLO_CONTENT.len() {
            reply.data(&[]);
            return;
        }

        let end = (start + size as usize).min(HELLO_CONTENT.len());
        reply.data(&HELLO_CONTENT[start..end]);
    }
}
