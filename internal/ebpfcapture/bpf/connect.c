// connect.c is idryx's eBPF network-behavior sensor: attaches to the
// sys_enter_connect tracepoint and reports every outbound AF_INET connect()
// (pid, comm, destination ip:port) to userspace via a ring buffer.
//
// Mirrors the architecture of tokenfuse's own eBPF sensor
// (tokenfuse/crates/radar/radar-ebpf/src/main.rs, Rust/aya) rather than its
// code: same tracepoint, same captured fields, same AF_INET-only filter, but
// written in C against libbpf/CO-RE (idryx is 100% Go, so cilium/ebpf +
// libbpf is the natural toolchain here, not aya). See
// internal/ebpfcapture/capture_linux.go for the userspace loader.
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

// conn_event is connect.c's wire shape to userspace, 28 bytes, no implicit
// compiler padding left ambiguous: dport/daddr are raw, untouched bytes
// copied straight out of the kernel's own struct sockaddr_in (always
// network/big-endian byte order per POSIX), deliberately NOT byte-order
// -converted here -- capture_linux.go decodes them explicitly instead, so
// the one place that has to reason about byte order is Go, where it is
// easy to unit test, not C, where it is not. _pad exists so sizeof(struct
// conn_event) == 28 unambiguously: without it the C compiler would still
// silently round up to 28 for pid's 4-byte alignment, but leaving that
// implicit would make the two sides' agreement on the wire size a
// coincidence of compiler behavior rather than a documented contract.
struct conn_event {
	__u32 pid;        // native (host) byte order -- never crosses a network boundary
	__u8 dport[2];     // raw sockaddr_in.sin_port bytes, network byte order
	__u8 daddr[4];     // raw sockaddr_in.sin_addr bytes, network byte order
	char comm[16];     // NUL-padded process name (bpf_get_current_comm's own format)
	__u8 _pad[2];      // explicit trailing padding, see above
};

// sockaddr_in mirrors the kernel's own layout (linux/in.h) for the one
// struct this program reads from userspace memory. Not sourced from
// vmlinux.h: sockaddr_in is a libc/uapi type, not a kernel-internal one, so
// it is not present in the kernel's own BTF.
struct sockaddr_in_local {
	__u16 sin_family;
	__u8 sin_port[2];
	__u8 sin_addr[4];
};

#define AF_INET 2

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// conn_event is only ever named inside on_connect's function body (as the
// ring buffer reservation's pointer type), and clang's BTF generation for
// the bpf target keeps just what's reachable from a small set of roots --
// map key/value types, global variable/function signatures -- discarding
// anything reachable only from a local variable. Without this dummy global,
// bpf2go's -type conn_event fails at generate time with "looking up type
// conn_event: not found" even with -g, because the type is compiled but
// never makes it into the object's .BTF section. This is the standard
// cilium/ebpf idiom for the same problem (see e.g. its own ringbuffer
// example's "force emitting struct event into the ELF").
const struct conn_event *unused_conn_event __attribute__((unused));

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

	struct sockaddr_in_local sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), addr_ptr) != 0)
		return 0;
	if (sa.sin_family != AF_INET)
		return 0;

	struct conn_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	ev->pid = pid_tgid >> 32;
	__builtin_memcpy(ev->dport, sa.sin_port, sizeof(ev->dport));
	__builtin_memcpy(ev->daddr, sa.sin_addr, sizeof(ev->daddr));
	ev->_pad[0] = 0;
	ev->_pad[1] = 0;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
