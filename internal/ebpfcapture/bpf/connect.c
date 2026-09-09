// connect.c is idryx's eBPF network-behavior sensor. It reports every outbound
// AF_INET and AF_INET6 connection (pid, comm, destination ip:port) to userspace
// through a ring buffer, and counts what it deliberately did not report.
//
// WHERE IT ATTACHES, AND WHY IT IS NOT THE SYSCALL
//
// Everything comes from a single kprobe on __sys_connect_file. Until 2026-09-09
// it came from the sys_enter_connect tracepoint, which is gone.
//
// The tracepoint fires at the syscall boundary, where the destination address
// is still a pointer into the CALLING PROCESS'S memory that the kernel has not
// copied yet. Three consequences, none of them visible in anything the sensor
// printed:
//
//   1. A second thread can rewrite that buffer between this program reading it
//      and the kernel reading it (__sys_connect's own move_addr_to_kernel), so
//      the sensor records an address the kernel never used. Measured
//      2026-09-09 against the tracepoint build with a two-thread probe and
//      ground truth taken from connect()'s own return value: 58 of 20,000 raced
//      connections wrong, 126 of 30,000, 221 of 25,000.
//   2. io_uring never passes through it. IORING_OP_CONNECT copies the address
//      at submission (io_connect_prep's move_addr_to_kernel) and calls
//      __sys_connect_file directly, so a process using io_uring was invisible,
//      silently and completely: one io_uring connection and one ordinary one
//      gave one flow.
//   3. The length the caller passed was never consulted, so a sockaddr the
//      kernel is about to REFUSE for being too short was read as though it were
//      whole, and whatever lay after it in the caller's memory was reported as
//      an address.
//
// __sys_connect_file closes all three. It runs after the kernel has copied the
// address into its own memory, both the syscall path and io_uring reach it, and
// it carries addrlen as its third argument. It has existed since Linux 5.5,
// below this sensor's own floor, so nothing is narrowed by choosing it.
//
// It also sits BEFORE security_socket_connect, which the first attempt at this
// move did not: hooking inet_stream_connect and inet_dgram_connect, one layer
// down, loses every attempt an LSM denied, and a denied attempt is the event
// this tool most wants. That attempt is TAIPANBOX/idryx#74, closed unmerged,
// and its closing comment is the long form of this paragraph.
//
// KPROBE RATHER THAN FENTRY, AND WHAT IT COSTS
//
// fentry on a kernel function needs a BPF trampoline, and arm64 gains one only
// at 6.4: on 6.1 bpf_arch_text_poke pokes only BPF text, register_fentry
// returns -ENOTSUPP without tr->fops, and DYNAMIC_FTRACE_WITH_DIRECT_CALLS
// enters arm64's Kconfig at 6.4. Choosing fentry would move this sensor's floor
// from 5.8 to 6.4 on arm64 and take Debian 12, Amazon Linux 2023 on Graviton
// and Ubuntu 22.04 with it. Portability is the whole of why AGENTS.md invariant
// 7 puts the sensor here rather than in tokenfuse's radar, so paying for it in
// portability would be paying with the reason.
//
// kprobe reaches its arguments through PT_REGS_PARM, whose field names
// bpf_tracing.h picks per architecture at COMPILE time. That is exactly the
// property radar was criticised for, and the difference is that radar hard-codes
// ONE offset into ONE object shipped everywhere, while this is compiled once per
// architecture and selected by build tag: correct by construction rather than by
// a comment claiming an offset is universal.
//
// The price is stated rather than buried: this object is built for amd64 and
// arm64, and the sensor no longer builds for anything else. The tracepoint build
// it replaces was architecture-independent and so nominally supported every
// architecture bpf2go targets. It had run on two. A narrower true claim beats a
// wider aspirational one, and adding an architecture is one word in the
// //go:generate line plus its object.
//
// WHY ONE PROGRAM IS ENOUGH, WHERE THE FIRST ATTEMPT NEEDED TWO
//
// idryx#74 kept the tracepoint beside its fentry programs, because
// inet_stream_connect and inet_dgram_connect sit BELOW the protocol dispatch and
// cannot see AF_UNIX or netlink at all: without the tracepoint, invariant 4's
// "say what you could not observe" had nothing to say. __sys_connect_file sits
// ABOVE that dispatch, so every family arrives here and the coverage counters
// come off the kernel's own copy like the evidence does. One attach point, one
// program, and a counter a hostile process can no longer skew.
//
// Mirrors the architecture of tokenfuse's own eBPF sensor
// (tokenfuse/crates/radar/radar-ebpf/src/main.rs, Rust/aya) rather than its
// code: written in C against libbpf/CO-RE (idryx is 100% Go, so cilium/ebpf +
// libbpf is the natural toolchain here, not aya). radar still sits on the
// tracepoint alone, so all three defects above are its by construction.
//
// GPL: this program calls bpf_probe_read_kernel, which is GPL-only-gated, so
// the declaration is load-bearing rather than conventional.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// BPF_KPROBE, which reads a kprobe's arguments through the per-architecture
// PT_REGS_PARM macros. bpf2go defines __TARGET_ARCH_<arch> for each target it
// compiles (its gen/compile.go does), which is what makes those macros resolve.
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// conn_event is connect.c's wire shape to userspace, 40 bytes, no implicit
// compiler padding left ambiguous: dport/daddr are raw, untouched bytes
// copied straight out of the kernel's own sockaddr (always network/big-endian
// byte order per POSIX), deliberately NOT byte-order-converted here --
// decode.go decodes them explicitly instead, so the one place that has to
// reason about byte order is Go, where it is easy to unit test, not C, where
// it is not.
//
// daddr is 16 bytes for both families rather than a union: an IPv4 address
// occupies the first four and the rest are zero, which keeps one record size,
// one decoder and one offset table. `family` says which it is (4 or 6) so the
// decoder never has to guess from the trailing zeros -- ::ffff:0.0.0.0/96 and
// a short IPv4 write would otherwise be indistinguishable. _pad0 keeps the
// 16-byte address 4-aligned and the total unambiguously 40 rather than left to
// the compiler's own rounding.
// The two 8-byte fields lead, for alignment: anywhere else they make the
// compiler insert padding the two sides then have to agree about implicitly.
// With them first, every offset below is its own size's multiple and the total
// is 64 with nothing left to interpretation (56 until ns_tgid joined at the end,
// where it moved no earlier offset).
//
// ktime_ns is the kernel's own monotonic clock at the moment of the syscall,
// and it is here because the userspace timestamp is not the same measurement.
// A Go reader stamps a flow when it drains the ring buffer, which is after
// buffering, after scheduling, and after whatever else that process was doing.
// For a report that is close enough; for measuring the INTERVAL between one
// agent's connections, which is what beaconing detection is, the difference
// between those two clocks is exactly the signal being looked for.
struct conn_event {
	__u64 cgroup_id;   // bpf_get_current_cgroup_id(), 0 when unavailable
	__u64 ktime_ns;    // bpf_ktime_get_ns(): when the KERNEL saw this connect()
	__u32 pid;        // native (host) byte order -- never crosses a network boundary
	__u8 dport[2];     // raw sockaddr sin_port/sin6_port bytes, network byte order
	__u8 family;       // 4 for AF_INET, 6 for AF_INET6; never anything else
	__u8 _pad0;        // explicit, see above
	__u8 daddr[16];    // raw address bytes; IPv4 in [0..4), zero-filled after
	char comm[16];     // NUL-padded process name (bpf_get_current_comm's own format)
	__u32 ns_tgid;     // tgid as the sensor's own PID namespace numbers it; 0 for a task outside it
	__u32 _pad1;       // explicit: keeps the total at 64, a multiple of 8, with nothing left to the compiler
};

// skipped counts what the program saw and did NOT put on the ring buffer, per
// reason. Without it "zero flows captured" has several indistinguishable
// meanings: nothing connected, everything connected over a family this sensor
// ignores, or the ring buffer was full and the evidence was dropped on the
// floor. AGENTS.md invariant 4 requires idryx to say what it could not
// observe rather than present a partial graph as complete, and until this map
// existed the sensor had no way to say it.
//
// Every one of these is now counted from the KERNEL'S OWN COPY of the address,
// so the numbers cannot be raced any more than the evidence can. On the
// tracepoint they were read out of the calling process's memory, which meant a
// hostile process could skew them; that is gone with the attach point.
//
// A single-entry ARRAY rather than PERCPU_ARRAY: these are rare events by
// construction (a busy host makes far more connections than it makes
// unreadable ones), the counters are read once at the end of a capture, and a
// per-CPU map would trade an exact answer for a contended-write optimisation
// this workload never needs.
struct skipped_counts {
	__u64 other_family;   // reached the connect path over a family this sensor does not report (AF_UNIX, netlink, ...)
	__u64 unreadable;     // the kernel's own copy of the sockaddr could not be read
	__u64 ringbuf_full;   // a real, in-scope connection we could not report
	// The caller passed fewer bytes than the family needs, so the address is
	// not all there. The kernel refuses these too, a few frames later
	// (tcp_v4_connect: `addr_len < sizeof(struct sockaddr_in)` is EINVAL), so
	// this counts a connection that was never going to happen. Reporting it
	// would put an address in the graph that was half read out of whatever the
	// caller happened to have in that buffer, which the tracepoint build did.
	__u64 too_short;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct skipped_counts);
} skipped SEC(".maps");

// sockaddr_in/sockaddr_in6 mirror the kernel's own layout (linux/in.h,
// linux/in6.h) for the two structs this program reads. Not sourced from
// vmlinux.h: these are libc/uapi types, not kernel-internal ones, so they are
// not present in the kernel's own BTF.
struct sockaddr_in_local {
	__u16 sin_family;
	__u8 sin_port[2];
	__u8 sin_addr[4];
};

struct sockaddr_in6_local {
	__u16 sin6_family;
	__u8 sin6_port[2];
	__u32 sin6_flowinfo;
	__u8 sin6_addr[16];
	__u32 sin6_scope_id;
};

// What the KERNEL requires of addrlen for each family, which is more than this
// program reads: the full sockaddr_in is 16 bytes because of sin_zero, and
// sockaddr_in6 is 28. Checked against the caller's length before the address is
// believed, because a shorter one means the bytes after the truncation belong
// to whatever else was in that buffer, and the kernel is about to refuse the
// call anyway.
#define SOCKADDR_IN_MIN 16
#define SOCKADDR_IN6_MIN 28

// bpf_tracing.h reaches a kprobe's arguments through PT_REGS_PARM, which on
// arm64 casts the context to `struct user_pt_regs`. vmlinux.h is generated from
// ONE kernel's BTF and the committed one is x86_64's, so that type is not in it
// and the arm64 build does not compile without this.
//
// Written out here rather than by committing a second 3.5 MB vmlinux.h per
// architecture, for the same reason sockaddr_in_local above is written out: it
// is a uapi type (arch/arm64/include/uapi/asm/ptrace.h), stable ABI, and not a
// kernel-internal shape that BTF would have to be trusted for.
//
// It is safe to define unconditionally on the arm64 target only. The rest of
// this program reads no kernel struct through BTF at all any more, since
// dropping the sys_enter_connect tracepoint removed the last CO-RE-typed read,
// so an x86_64 vmlinux.h is otherwise harmless when compiling for arm64.
#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

#define AF_INET 2
#define AF_INET6 10

// The sensor's own PID namespace, as the (dev, inode) of /proc/self/ns/pid,
// written by userspace before the program is loaded. bpf_get_current_pid_tgid()
// reports the pid in the INITIAL namespace, while inside a container
// os.Getpid() is the namespaced one, so a self-filter that compares the two
// never matches there: measured 2026-09-08, the sensor reported 16 of its own
// 21 flows from a container (TAIPANBOX/idryx#66). With these set, the program
// also reports each task's tgid as that namespace numbers it, via
// bpf_get_ns_current_pid_tgid(), which answers only for tasks whose active PID
// namespace is the one named here and refuses (-EINVAL) for every other task;
// the field is then 0, and userspace decides self on that field alone. Zero
// here means "not set", and userspace refuses to run that way rather than
// capture with a filter that silently does nothing.
const volatile __u64 self_pidns_dev = 0;
const volatile __u64 self_pidns_ino = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// conn_event and skipped_counts are only ever named inside function bodies (as
// a reservation's pointer type and a lookup's value type), and clang's BTF
// generation for the bpf target keeps just what's reachable from a small set
// of roots -- map key/value types, global variable/function signatures --
// discarding anything reachable only from a local variable. Without these
// dummy globals, bpf2go's -type flag fails at generate time with "looking up
// type ...: not found" even with -g, because the type is compiled but never
// makes it into the object's .BTF section. This is the standard cilium/ebpf
// idiom for the same problem (see e.g. its own ringbuffer example's "force
// emitting struct event into the ELF").
const struct conn_event *unused_conn_event __attribute__((unused));
const struct skipped_counts *unused_skipped_counts __attribute__((unused));

// bump adds one to a field of the single skipped_counts entry. A missing entry
// is impossible for a one-element ARRAY (the kernel zero-fills it at load), but
// the verifier requires the NULL check regardless, and it costs nothing.
static __always_inline void bump(__u64 offset)
{
	__u32 key = 0;
	struct skipped_counts *c = bpf_map_lookup_elem(&skipped, &key);
	if (!c)
		return;
	__u64 *field = (__u64 *)((char *)c + offset);
	__sync_fetch_and_add(field, 1);
}

#define BUMP(field) bump(__builtin_offsetof(struct skipped_counts, field))

// int __sys_connect_file(struct file *file, struct sockaddr_storage *address,
//                        int addrlen, int file_flags)
//
// net/socket.c. `address` points into KERNEL memory: __sys_connect has already
// copied it with move_addr_to_kernel, and io_uring copied it at submission, so
// by the time this runs it is the address the kernel is about to act on and no
// thread can swap it underneath. Hence bpf_probe_read_kernel below.
//
// Every family arrives here, because __sys_connect calls this with no protocol
// dispatch in front of it, which is why one program is enough and the
// sys_enter_connect tracepoint this sensor used to carry beside it is gone:
// AF_UNIX and netlink are counted from the kernel's copy now rather than from
// the caller's.
//
// What does NOT reach here is a connect() that never became a connection
// attempt: a bad file descriptor, or a sockaddr move_addr_to_kernel refused
// outright. The tracepoint saw those and reported them as flows, reading an
// address out of a buffer the kernel had rejected. Not seeing them is the
// improvement, not the loss.
// `address` is declared void* rather than as the kernel's own
// `struct sockaddr_storage`, and that is not laziness. vmlinux.h carries
// `struct __kernel_sockaddr_storage`, not `struct sockaddr_storage`, so naming
// the latter here declares an incomplete type inside the parameter list; the two
// expansions BPF_KPROBE makes of this signature then disagree about it and the
// compile fails with "conflicting types". Nothing dereferences the pointer
// anyway: the address is read with bpf_probe_read_kernel into the local sockaddr
// mirrors below, which is what makes this program independent of the kernel's
// own storage layout.
SEC("kprobe/__sys_connect_file")
int BPF_KPROBE(on_connect, void *file, void *address, int addrlen, int file_flags)
{
	if (!address)
		return 0;

	// The family is the first two bytes of every sockaddr, so it is read
	// first and decides which struct to read afterwards. Reading the larger
	// sockaddr_in6 unconditionally would read past a shorter allocation.
	__u16 family = 0;
	if (bpf_probe_read_kernel(&family, sizeof(family), address) != 0) {
		BUMP(unreadable);
		return 0;
	}
	if (family != AF_INET && family != AF_INET6) {
		BUMP(other_family);
		return 0;
	}

	// The caller's own length, which the tracepoint build never consulted.
	// Below the family's minimum the address is not all there and the kernel
	// will refuse the call a few frames from here, so reporting it would put a
	// destination in the graph that half came from whatever else was in that
	// buffer.
	if ((family == AF_INET && addrlen < SOCKADDR_IN_MIN) ||
	    (family == AF_INET6 && addrlen < SOCKADDR_IN6_MIN)) {
		BUMP(too_short);
		return 0;
	}

	struct conn_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		// A connection this sensor WANTED to report and could not. This is
		// the counter that matters most: the others are traffic out of scope
		// or a call the kernel will refuse, this one is evidence lost.
		BUMP(ringbuf_full);
		return 0;
	}

	__builtin_memset(ev->daddr, 0, sizeof(ev->daddr));
	ev->_pad0 = 0;

	if (family == AF_INET) {
		struct sockaddr_in_local sa = {};
		if (bpf_probe_read_kernel(&sa, sizeof(sa), address) != 0) {
			bpf_ringbuf_discard(ev, 0);
			BUMP(unreadable);
			return 0;
		}
		ev->family = 4;
		__builtin_memcpy(ev->dport, sa.sin_port, sizeof(ev->dport));
		__builtin_memcpy(ev->daddr, sa.sin_addr, sizeof(sa.sin_addr));
	} else {
		struct sockaddr_in6_local sa6 = {};
		if (bpf_probe_read_kernel(&sa6, sizeof(sa6), address) != 0) {
			bpf_ringbuf_discard(ev, 0);
			BUMP(unreadable);
			return 0;
		}
		ev->family = 6;
		__builtin_memcpy(ev->dport, sa6.sin6_port, sizeof(ev->dport));
		__builtin_memcpy(ev->daddr, sa6.sin6_addr, sizeof(sa6.sin6_addr));
	}

	// Taken as late as possible but still in the connecting task's own
	// context, so it times the connection rather than this program's
	// bookkeeping.
	ev->ktime_ns = bpf_ktime_get_ns();

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	ev->pid = pid_tgid >> 32;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	// The same task's tgid as the sensor's own PID namespace numbers it, or 0
	// for a task that namespace cannot see. -EINVAL is the kernel's normal
	// answer for a task in another namespace, not a fault, and 0 says so.
	ev->ns_tgid = 0;
	ev->_pad1 = 0;
	if (self_pidns_ino != 0) {
		struct bpf_pidns_info ns = {};
		if (bpf_get_ns_current_pid_tgid(self_pidns_dev, self_pidns_ino, &ns, sizeof(ns)) == 0)
			ev->ns_tgid = ns.tgid;
	}

	// The cgroup this process belongs to, read in the process's own context
	// rather than from /proc afterwards. That difference is the whole reason
	// it is here: a userspace reader races the process it is asking about,
	// and a short-lived agent is exactly the one worth attributing. A `comm`
	// is a string the process chose and can change with prctl; a cgroup id is
	// assigned by the kernel and the process cannot rewrite it.
	//
	// It is NOT a container id and must not be called one: it is the cgroup's
	// inode, unique while that cgroup lives and reused afterwards, and a
	// process outside any container has one too (the root cgroup's, shared by
	// everything else on the host). Userspace decides what it is worth; this
	// program only reports it. Zero on a kernel that does not provide it,
	// which decode.go treats as absent rather than as a cgroup called zero.
	ev->cgroup_id = bpf_get_current_cgroup_id();

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
