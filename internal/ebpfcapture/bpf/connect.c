// connect.c is idryx's eBPF network-behavior sensor: attaches to the
// sys_enter_connect tracepoint and reports every outbound AF_INET and
// AF_INET6 connect() (pid, comm, destination ip:port) to userspace via a
// ring buffer, and counts what it deliberately did not report.
//
// Mirrors the architecture of tokenfuse's own eBPF sensor
// (tokenfuse/crates/radar/radar-ebpf/src/main.rs, Rust/aya) rather than its
// code: same tracepoint, same captured fields, but written in C against
// libbpf/CO-RE (idryx is 100% Go, so cilium/ebpf + libbpf is the natural
// toolchain here, not aya). See internal/ebpfcapture/capture_linux.go for the
// userspace loader.
//
// Two things this file does that radar does not, and both are why AGENTS.md
// invariant 7 puts the sensor here. It reads the syscall argument through the
// BTF-typed trace_event_raw_sys_enter out of vmlinux.h, so it is CO-RE and
// portable across kernels and architectures, where radar counts a fixed byte
// offset that is only true on x86_64. And it observes IPv6, which radar's
// AF_INET-only filter drops without saying so.
//
// GPL: sys_enter_connect tracepoint programs conventionally declare GPL
// license (several core BPF helpers are GPL-only-gated); this program calls
// none of the GPL-restricted helpers today but keeps the declaration for the
// same reason the Rust sensor does -- future helpers on this program stay
// available without a relicensing exercise.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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
struct conn_event {
	__u32 pid;        // native (host) byte order -- never crosses a network boundary
	__u8 dport[2];     // raw sockaddr sin_port/sin6_port bytes, network byte order
	__u8 family;       // 4 for AF_INET, 6 for AF_INET6; never anything else
	__u8 _pad0;        // explicit, see above
	__u8 daddr[16];    // raw address bytes; IPv4 in [0..4), zero-filled after
	char comm[16];     // NUL-padded process name (bpf_get_current_comm's own format)
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
	__u64 other_family;   // neither AF_INET nor AF_INET6 (AF_UNIX, netlink, ...)
	__u64 unreadable;     // bpf_probe_read_user could not read the sockaddr
	__u64 ringbuf_full;   // a real, in-scope connection we could not report
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

// sys_enter_connect's real syscall arguments arrive in the generic
// tracepoint context's args[] array (struct trace_event_raw_sys_enter,
// BTF-typed by vmlinux.h -- portable across kernel versions/builds, unlike
// a hand-rolled offset struct): args[0] = fd, args[1] = uservaddr (struct
// sockaddr *), args[2] = addrlen. See /sys/kernel/debug/tracing/events/
// syscalls/sys_enter_connect/format on any Linux box for the authoritative
// field order, part of the syscall tracepoint ABI.
SEC("tracepoint/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx)
{
	void *addr_ptr = (void *)ctx->args[1];
	if (!addr_ptr)
		return 0;

	// The family is the first two bytes of every sockaddr, so it is read
	// first and decides which struct to read afterwards. Reading the larger
	// sockaddr_in6 unconditionally would fault on an AF_INET sockaddr that
	// sits at the end of a page, which is a real layout and not a
	// hypothetical one.
	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), addr_ptr) != 0) {
		BUMP(unreadable);
		return 0;
	}
	if (family != AF_INET && family != AF_INET6) {
		BUMP(other_family);
		return 0;
	}

	struct conn_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		// A connection this sensor WANTED to report and could not. This is
		// the counter that matters most: the other two are traffic out of
		// scope, this one is evidence lost.
		BUMP(ringbuf_full);
		return 0;
	}

	__builtin_memset(ev->daddr, 0, sizeof(ev->daddr));
	ev->_pad0 = 0;

	if (family == AF_INET) {
		struct sockaddr_in_local sa = {};
		if (bpf_probe_read_user(&sa, sizeof(sa), addr_ptr) != 0) {
			bpf_ringbuf_discard(ev, 0);
			BUMP(unreadable);
			return 0;
		}
		ev->family = 4;
		__builtin_memcpy(ev->dport, sa.sin_port, sizeof(ev->dport));
		__builtin_memcpy(ev->daddr, sa.sin_addr, sizeof(sa.sin_addr));
	} else {
		struct sockaddr_in6_local sa6 = {};
		if (bpf_probe_read_user(&sa6, sizeof(sa6), addr_ptr) != 0) {
			bpf_ringbuf_discard(ev, 0);
			BUMP(unreadable);
			return 0;
		}
		ev->family = 6;
		__builtin_memcpy(ev->dport, sa6.sin6_port, sizeof(ev->dport));
		__builtin_memcpy(ev->daddr, sa6.sin6_addr, sizeof(sa6.sin6_addr));
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	ev->pid = pid_tgid >> 32;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
