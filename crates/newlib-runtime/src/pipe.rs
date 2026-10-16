//! POSIX labels and publication stay local; the kernel creates generic streams.
use super::*;
use super::fd_creation::{PendingHandles, PendingPair};

pub(super) fn create(output: *mut c_int, flags: c_int) -> Result<c_int, c_int> {
    io_resources::with(
        || {
            let limit = process_fd_limit()?;
            let pending = PendingPair(
                state()
                    .fds
                    .reserve_pair_from(0, limit)
                    .map_err(|_| EMFILE)?,
            );
            let mut pair = syscall::StreamPair::default();
            syscall_errno(syscall::raw_syscall1(
                syscall::SyscallNumber::StreamPairCreate,
                (&mut pair as *mut syscall::StreamPair) as u64,
            ))?;
            let common = syscall::HANDLE_RIGHT_WAIT
                | syscall::HANDLE_RIGHT_CONTROL
                | syscall::HANDLE_RIGHT_DUPLICATE
                | syscall::HANDLE_RIGHT_TRANSFER;
            let opened = PendingHandles {
                handles: [
                    ObjectHandleAttachment {
                        handle: pair.read,
                        rights: common | syscall::HANDLE_RIGHT_READ,
                    },
                    ObjectHandleAttachment {
                        handle: pair.write,
                        rights: common | syscall::HANDLE_RIGHT_WRITE,
                    },
                ],
                installed: false,
            };
            if flags & O_NONBLOCK != 0 {
                for handle in opened.handles {
                    syscall_errno(syscall::raw_syscall2(
                        syscall::SyscallNumber::HandleOptionsSet,
                        u64::from(handle.handle),
                        syscall::HANDLE_OPTION_NONBLOCKING,
                    ))?;
                }
            }
            Ok((pending, opened))
        },
        |(pending, opened)| {
            let _native = defer_native_delivery();
            let entries = [
                object_entry(
                    u64::from(opened.handles[0].handle),
                    opened.handles[0].rights,
                    FdKind::ObjectStreamRead,
                    flags,
                ),
                object_entry(
                    u64::from(opened.handles[1].handle),
                    opened.handles[1].rights,
                    FdKind::ObjectStreamWrite,
                    flags | 1,
                ),
            ];
            // A fault on either write abandons the tracked pair, not open FDs.
            unsafe {
                output.write(pending.0[0].descriptor());
                output.add(1).write(pending.0[1].descriptor());
            }
            state()
                .fds
                .commit_pair([&pending.0[0], &pending.0[1]], entries)
                .map_err(|_| EIO)?;
            opened.installed = true;
            Ok(0)
        },
    )
}
