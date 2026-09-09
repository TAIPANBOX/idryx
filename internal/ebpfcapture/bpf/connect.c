// connect.c is idryx's eBPF network-behavior sensor. It reports every outbound
// AF_INET and AF_INET6 connection (pid, comm, destination ip:port) to userspace
// through a ring buffer, and counts what it deliberately did not report.
//
// WHERE IT ATTACHES, AND WHY THAT MOVED
//
// The evidence comes from fentry programs on inet_stream_connect and
// inet_dgram_connect, which are the kernel's own INET connect path. The
// counters still come from the sys_enter_connect tracepoint, which is where
// this sensor used to take everything.
//
// The tracepoint fires at the syscall boundary, where the destination address
// is still a pointer into the CALLING PROCESS'S memory that the kernel has not
// copied yet. Two consequences, neither of them visible in anything the sensor
// printed:
//
//   1. A second thread can rewrite that buffer between this program reading it
//      and the kernel reading it (__sys_connect's own move_addr_to_kernel).
//      The sensor then records an address the kernel never used. This is the
//      published "Phantom attack" shape against syscall-boundary eBPF sensors,
//      and against a tool whose job is catching an agent reaching somewhere it
//      should not, a decoy address is the whole game.
//   2. io_uring never passes through it. IORING_OP_CONNECT copies the address
//      at submission and calls __sys_connect_file directly, so a process using
//      io_uring was invisible to this sensor, silently and completely.
//
// Both fentry programs take the address AFTER the kernel has copied it into its
// own memory: inet_stream_connect and inet_dgram_connect are what
// sock->ops->connect resolves to for AF_INET and AF_INET6, and BOTH the syscall
// path and io_uring reach them through __sys_connect_file. So the sensor now
// reads the bytes the kernel is about to act on, which closes 1, and sees
// io_uring, which closes 2.
//
// FENTRY RATHER THAN KPROBE, AND IT IS NOT A PREFERENCE
//
// A kprobe on the same two functions would read the same kernel copy. It would
// also have to reach its arguments through PT_REGS_PARM, whose field names
// bpf_tracing.h picks per architecture at COMPILE time, from __TARGET_ARCH_*.
// This repository ships ONE object for bpfel and one for bpfeb, compiled
// against neither host architecture, and that portability is the reason
// AGENTS.md invariant 7 puts the sensor here rather than in tokenfuse's radar,
// which hard-codes an x86_64 offset. fentry's arguments arrive through a
// kernel-normalised context, so BPF_PROG reads them identically everywhere.
// Choosing kprobe would mean reintroducing exactly the defect this sensor was
// written to avoid.
//
// It costs a requirement: fentry needs BTF and a kernel that will attach to
// those symbols. This sensor already requires BTF for CO-RE and Linux 5.7 for
// bpf_get_ns_current_pid_tgid, so the floor does not move, and a kernel that
// refuses fails the load loudly rather than capturing nothing quietly.
//
// WHAT THE TRACEPOINT IS STILL FOR
//
// It reserves nothing and reports nothing. It counts connect() calls over
// families this sensor does not report (AF_UNIX, netlink), which is a statement
// about COVERAGE that the INET path cannot make: down there, traffic out of
// scope is not skipped, it is never seen. Invariant 4 requires idryx to say
// what it could not observe, and a live capture counting 36 such connects is
// that invariant working on real traffic. Reading user memory for a counter is
// still racy, and that is now the whole of what a race can reach: a number
// beside the evidence, never the evidence.
//
// Mirrors the architecture of tokenfuse's own eBPF sensor
// (tokenfuse/crates/radar/radar-ebpf/src/main.rs, Rust/aya) rather than its
// code: written in C against libbpf/CO-RE (idryx is 100% Go, so cilium/ebpf +
// libbpf is the natural toolchain here, not aya). See
// internal/ebpfcapture/capture_linux.go for the userspace loader.
//
// Two things this file does that radar does not, and both are why AGENTS.md
// invariant 7 puts the sensor here. It is CO-RE, portable across kernels and
// architectures, where radar counts a fixed byte offset that is only true on
// x86_64. And it observes IPv6, which radar's AF_INET-only filter drops without
// saying so. Radar also still sits on the tracepoint alone, so both defects
// described above are its by construction.
//
// GPL: sys_enter_connect tracepoint programs conventionally declare GPL
// license (several core BPF helpers are GPL-only-gated); this program calls
// none of the GPL-restricted helpers today but keeps the declaration for the
// same reason the Rust sensor does -- future helpers on this program stay
// available without a relicensing exercise.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// BPF_PROG, for the two fentry programs. Its whole value here is that it reads
// a tracing program's arguments out of a kernel-normalised context rather than
// out of pt_regs, which is what keeps one compiled object correct on every
// architecture. See the header.
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
// reason. Without it "zero flows captured" has three indistinguishable
// meanings: nothing connected, everything connected over a family this sensor
// ignores, or the ring buffer was full and the evidence was dropped on the
// floor. AGENTS.md invariant 4 requires idryx to say what it could not
// observe rather than present a partial graph as complete, and until this map
// existed the sensor had no way to say it.
//
// A single-entry ARRAY rather than PERCPU_ARRAY: these are rare events by
// construction (a busy host makes far more connections than it makes
// unreadable ones), the counters are read once at the end of a capture, and a
// per-CPU map would trade an exact answer for a contended-write optimisation
// this workload never needs.
struct skipped_counts {
	__u64 other_family;   // syscall path: connect() over neither AF_INET nor AF_INET6 (AF_UNIX, netlink, ...)
	__u64 unreadable;     // a sockaddr this sensor could not read, from either program
	__u64 ringbuf_full;   // a real, in-scope connection we could not report
	// The INET path reached with a family it does not report. In practice this
	// is AF_UNSPEC, which on a datagram socket DISSOLVES an association rather
	// than making one: connect(fd, {AF_UNSPEC}, ...) is how a process
	// disconnects a UDP socket. Counted rather than ignored, because "the
	// sensor saw something on this path and said nothing about it" is exactly
	// the silence invariant 4 refuses, and it is a different number from
	// other_family above, which counts sockets that never reach this path at
	// all. One field per producer: a counter two programs increment for two
	// different reasons is a number nobody can decompose afterwards.
	__u64 not_inet;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct skipped_counts);
} skipped SEC(".maps");

// sockaddr_in/sockaddr_in6 mirror the kernel's own layout (linux/in.h,
// linux/in6.h) for the two structs this program reads from userspace memory.
// Not sourced from vmlinux.h: these are libc/uapi types, not kernel-internal
// ones, so they are not present in the kernel's own BTF.
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

// report_connect is the whole of the evidence path, shared by both fentry
// programs below because inet_stream_connect and inet_dgram_connect differ only
// in their arity and in which transport called them.
//
// `uaddr` points into KERNEL memory here, not into the calling process's, which
// is the entire reason this function exists at this attach point rather than at
// the syscall boundary. __sys_connect copies the address with
// move_addr_to_kernel before calling sock->ops->connect, and io_uring copies it
// at submission, so by the time either of these functions runs the address is
// the one the kernel is about to act on and no thread can swap it underneath.
// Hence bpf_probe_read_kernel rather than bpf_probe_read_user.
static __always_inline int report_connect(void *uaddr)
{
	if (!uaddr)
		return 0;

	// The family is the first two bytes of every sockaddr, so it is read
	// first and decides which struct to read afterwards. Reading the larger
	// sockaddr_in6 unconditionally would read past a shorter allocation.
	//
	// Read as two raw bytes at the pointer rather than through
	// struct sockaddr's own field, deliberately: the kernel has changed that
	// struct's shape (it is a union on newer kernels) and the first two bytes
	// being the family is the older and more stable contract of the two.
	__u16 family = 0;
	if (bpf_probe_read_kernel(&family, sizeof(family), uaddr) != 0) {
		BUMP(unreadable);
		return 0;
	}
	if (family != AF_INET && family != AF_INET6) {
		// AF_UNSPEC, in practice: on a datagram socket that dissolves an
		// association rather than making one. Not a connection, and counted
		// so that "the sensor saw this and said nothing" is never silent.
		BUMP(not_inet);
		return 0;
	}

	struct conn_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		// A connection this sensor WANTED to report and could not. This is
		// the counter that matters most: the others are traffic out of
		// scope, this one is evidence lost.
		BUMP(ringbuf_full);
		return 0;
	}

	__builtin_memset(ev->daddr, 0, sizeof(ev->daddr));
	ev->_pad0 = 0;

	if (family == AF_INET) {
		struct sockaddr_in_local sa = {};
		if (bpf_probe_read_kernel(&sa, sizeof(sa), uaddr) != 0) {
			bpf_ringbuf_discard(ev, 0);
			BUMP(unreadable);
			return 0;
		}
		ev->family = 4;
		__builtin_memcpy(ev->dport, sa.sin_port, sizeof(ev->dport));
		__builtin_memcpy(ev->daddr, sa.sin_addr, sizeof(sa.sin_addr));
	} else {
		struct sockaddr_in6_local sa6 = {};
		if (bpf_probe_read_kernel(&sa6, sizeof(sa6), uaddr) != 0) {
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
	//
	// io_uring does not break this. A submission that the ring can issue
	// inline runs in the submitting task's own context, and one punted to
	// io-wq runs in a worker created by create_io_thread(), which clones that
	// task WITH CLONE_THREAD and so shares its tgid. Either way the connection
	// is attributed to the process that asked for it. Measured 2026-09-09: an
	// IORING_OP_CONNECT issued inline was reported as `proc:iouring_connect`,
	// the submitting program's own name, not a worker's.
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

// int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
//                         int addr_len, int flags)
//
// TCP, and both address families: inet6_stream_ops.connect is this same
// function, so one program covers IPv4 and IPv6.
SEC("fentry/inet_stream_connect")
int BPF_PROG(on_inet_stream_connect, struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags)
{
	return report_connect(uaddr);
}

// int inet_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
//                        int addr_len)
//
// UDP, one argument shorter than its stream sibling, which is the only reason
// these are two programs rather than one.
SEC("fentry/inet_dgram_connect")
int BPF_PROG(on_inet_dgram_connect, struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	return report_connect(uaddr);
}

// The tracepoint reserves nothing and reports nothing: it exists only to count
// what this sensor does not observe. See the header for why that is worth a
// program of its own.
//
// sys_enter_connect's real syscall arguments arrive in the generic tracepoint
// context's args[] array (struct trace_event_raw_sys_enter, BTF-typed by
// vmlinux.h -- portable across kernel versions/builds, unlike a hand-rolled
// offset struct): args[0] = fd, args[1] = uservaddr (struct sockaddr *),
// args[2] = addrlen. See /sys/kernel/debug/tracing/events/syscalls/
// sys_enter_connect/format on any Linux box for the authoritative field order,
// part of the syscall tracepoint ABI.
//
// This one still reads USER memory, and still can be raced, and that is now
// harmless: the worst a decoy achieves here is a wrong number in a coverage
// counter, while the address that becomes evidence is read from the kernel's
// own copy above.
SEC("tracepoint/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx)
{
	void *addr_ptr = (void *)ctx->args[1];
	if (!addr_ptr)
		return 0;

	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), addr_ptr) != 0) {
		BUMP(unreadable);
		return 0;
	}
	if (family != AF_INET && family != AF_INET6)
		BUMP(other_family);

	return 0;
}
