# Native Unix extensions

These interfaces belong to the C runtime compatibility surface. Their names
do not place filesystem, dynamic-linker or VM policy inside posix.service.
No API below grants a new Capability or accepts an arbitrary process ID.

| Interface | Owner | Supported contract |
| --- | --- | --- |
| `flock` | filesystem.service open description; libc wait policy | Shared/exclusive/unlock, nonblocking acquisition, interruptible blocking acquisition, conversion, alias/fork/exec inheritance and final-Handle release. Independent from process-owned fcntl record locks. |
| `mincore` | VM observation; libc page-vector encoding | Own mapped pages, retained inaccessible RAM, cached file/RAM backing, bounded 256-page snapshots without input faults or I/O. |
| `madvise` | libc advice policy; VM private discard | NORMAL/RANDOM/SEQUENTIAL/WILLNEED nonbinding hints; DONTNEED discards private anonymous contents and preserves reservation/protection. File/shared/device discard and other advice are unsupported. |
| `dladdr` | process-local dynamic linker | Actual LOAD extents, mapped base, captured object names and nearest exported non-TLS/non-IFUNC dynamic symbol. Symbol absence does not prevent identifying the object. |
| `dl_iterate_phdr` | process-local dynamic linker | Initial native graph and mapped late groups; stable copied headers/names during callbacks, callback early termination and reentrant inspection. The supported dl_phdr_info prefix is 32 bytes; GNU TLS/counter suffixes are not advertised. |
| `pthread_getschedparam` / `pthread_setschedparam` | pthread runtime | Generation-checked live local pthread tokens; SCHED_OTHER/priority zero only. FIFO/RR return ENOTSUP. Errors are returned directly and do not change errno. |

## Authority and lifetime

Whole-file locks are stored on the provider's existing OpenFile. Provider IDs
come exclusively from native CONTROL Handle dispatch, not user-supplied paths,
FDs, PIDs or inode numbers. Existing Handle CONTROL authority is required.
Locking a read-only description does not grant write access. The conflict key
uses the opened volume and inode, so hard links cannot bypass it. Releasing the
final native alias drops the lock even if subsequent orphan cleanup fails.
Lock conversion releases the old mode before attempting the new one. The
provider never blocks its event loop; libc currently retries contention after
a 2ms native sleep, retaining a callback-tracked FD reference. This is bounded
polling, not an event-notified wait, and can be optimized separately.

MemoryResidencyRead (707) and MemoryDiscard (708) are generic own-address-space
mechanisms. Their arguments contain no POSIX advice values, service names,
filesystem policy or target-process selectors. Discard validates the complete
private anonymous range before transactional PTE revocation. Remote TLB
acknowledgement precedes RAM release; failure preserves original mapping state.
Captured anonymous backing is zeroed only after successful revocation. Cached
backing observations never populate pages or mutate the cache's LRU.

Loader inspection metadata is produced from captured, parsed ELF bytes. It is
transported as optional userspace AT_LOADED_OBJECTS (0x6d000008), inline or in
the existing read-only metadata mapping. The kernel neither parses nor trusts
it as executable authority. The runtime takes a private snapshot before
resolvers/constructors. Late groups retain their own immutable metadata until
unload; inspection from an initializer does not borrow its mutable loader
owner. Callbacks run without a loader mutex. Concurrent graph growth between
the size observation and snapshot can return EAGAIN rather than using dangling
views or truncating the object set.

The initial graph must be produced by a matching native loader. Older launch
paths without this metadata cannot provide a complete dl_iterate_phdr result
and return ENOTSUP. PT_INTERP graph inspection is not inferred from the root's
headers. Dynamic TLS, resolver-result symbol attribution, global namespaces
and dlopen profile extensions are not implemented by this change.

## SDK and validation

The source SDK headers expose these functions. SDK assembly checks actual
implementations and roots all seven executable exports when the new link.h is
present; old pinned SDKs do not claim the feature. C/C++ probe targets cover
header layout, executable/DSO linking and a separately callable native test.
Compile/link verification never labels the native test as executed.

The distributable SDK source pins and published artifacts are not advanced by
this change. Deployment requires a matching kernel, filesystem provider,
runtime and launch-metadata producer. Unsupported old-kernel errors are
propagated, including legacy error encoding; discard is never faked as success.

Host regression coverage includes real ext4 hard-link conflicts, conversion
and release; runtime blocking/nonblocking/error/reference paths; own-range
validation and revocation failure; sparse backing observation; hostile loader
metadata; real ELF dynamic symbols; C layouts; reentrant callbacks; and inline
versus read-only overflow metadata transport. Host tests and native target
compilation are not a substitute for a full native VM execution result.
