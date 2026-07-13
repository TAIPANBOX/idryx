//go:build linux

package ebpfcapture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// -g is required, not cosmetic: bpf2go's -type flag reflects struct
// conn_event into a matching Go struct by reading BTF debug info out of the
// compiled object, and clang only emits that debug info when asked to.
// Without -g, bpf2go fails at generate time with "looking up type
// conn_event: not found" -- the object still compiles, it just carries no
// type information to reflect.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type conn_event -cc clang bpf bpf/connect.c -- -g -O2 -I bpf

// connEventSize is sizeof(struct conn_event) in connect.c: 4 (pid) + 2
// (dport) + 4 (daddr) + 16 (comm) + 2 (explicit trailing pad) = 28 bytes.
// decodeConnEvent refuses anything shorter, so a future connect.c change
// that isn't mirrored here fails loudly (a skipped record, logged by the
// caller) rather than silently misreading a shifted layout.
const connEventSize = 28

// knownLLMHosts is the same starting set tokenfuse's own radar resolves
// (crates/radar/src/main.rs's resolve_llm_ips) -- kept short and
// hand-maintained here rather than imported from detectors.ShadowAI's own
// (larger, hostname-matched) list: eBPF can only match by resolved IP, and
// a DNS answer is a snapshot, not a durable fact, so a short, explicitly
// curated list is easier to reason about than silently trusting a
// wildcard-heavy host list against IPs resolved once at startup.
var knownLLMHosts = []string{
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
}

// Options configures Run.
type Options struct {
	// Duration bounds how long to capture. Zero means run until ctx is
	// canceled (e.g. by SIGINT in cmd/idryx).
	Duration time.Duration
	// OnFlow, if set, is called once per captured Flow as it arrives --
	// lets a caller stream to a file live rather than waiting for capture
	// to finish. Called synchronously from Run's read loop; a slow OnFlow
	// backs up ring buffer draining, so callers needing to do real work
	// per flow should hand off to their own goroutine.
	OnFlow func(Flow)
}

// Run attaches to sys_enter_connect, captures until ctx is canceled or
// Duration elapses (whichever first), and returns every captured flow.
// Requires root (or CAP_BPF+CAP_PERFMON); returns a clear error otherwise
// rather than a confusing EPERM three calls deep into the kernel.
func Run(ctx context.Context, opts Options) ([]Flow, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("ebpfcapture: requires root (or CAP_BPF+CAP_PERFMON); re-run with sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpfcapture: remove memlock rlimit: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("ebpfcapture: load eBPF objects (need root + a BTF-enabled kernel, see /sys/kernel/btf/vmlinux): %w", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.OnConnect, nil)
	if err != nil {
		return nil, fmt.Errorf("ebpfcapture: attach sys_enter_connect: %w", err)
	}
	defer tp.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("ebpfcapture: open ring buffer: %w", err)
	}
	defer reader.Close()

	llmIPs := resolveLLMHosts(knownLLMHosts)
	selfPID := uint32(os.Getpid()) // #nosec G115 -- os.Getpid() is bounded by the kernel's pid_max (never remotely near uint32 range); ev.pid (below) is the same uint32 PID representation the kernel itself hands the eBPF program

	stop := make(chan struct{})
	var stopOnce sync.Once
	closeReader := func() { stopOnce.Do(func() { _ = reader.Close(); close(stop) }) }
	go func() {
		<-ctx.Done()
		closeReader()
	}()
	if opts.Duration > 0 {
		timer := time.AfterFunc(opts.Duration, closeReader)
		defer timer.Stop()
	}

	var flows []Flow
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			return flows, fmt.Errorf("ebpfcapture: read ring buffer: %w", err)
		}
		ev, ok := decodeConnEvent(record.RawSample)
		if !ok || ev.dport == 0 || ev.pid == selfPID {
			continue
		}
		ip := net.IPv4(ev.daddr[0], ev.daddr[1], ev.daddr[2], ev.daddr[3])
		if ip.IsLoopback() && ev.dport != 11434 && ev.dport != 8000 && ev.dport != 8001 {
			continue // local chatter, not a model port -- skip, mirrors tokenfuse radar
		}
		comm := strings.TrimRight(string(ev.comm[:]), "\x00")
		dest := fmt.Sprintf("%s:%d", ip.String(), ev.dport)
		if host, ok := llmIPs[ip.String()]; ok {
			dest = fmt.Sprintf("%s:%d", host, ev.dport)
		}
		f := Flow{Time: time.Now().UTC(), Identity: Identity(comm), Destination: dest, PID: ev.pid}
		flows = append(flows, f)
		if opts.OnFlow != nil {
			opts.OnFlow(f)
		}
	}
	return flows, nil
}

// decodedConnEvent is connEvent's already-byte-order-resolved form: dport
// and daddr converted out of connect.c's deliberately-raw wire bytes (see
// connect.c's own doc comment for why that conversion happens here, not in
// the eBPF program).
type decodedConnEvent struct {
	pid   uint32
	dport uint16
	daddr [4]byte
	comm  [16]byte
}

// decodeConnEvent parses one ring buffer record against connect.c's struct
// conn_event layout exactly (see connEventSize). false means the record is
// the wrong size -- a mismatched connect.c/capture_linux.go pair, or ring
// buffer corruption -- and is skipped rather than panicking a live capture
// over one bad record.
func decodeConnEvent(raw []byte) (decodedConnEvent, bool) {
	if len(raw) < connEventSize {
		return decodedConnEvent{}, false
	}
	var ev decodedConnEvent
	ev.pid = binary.LittleEndian.Uint32(raw[0:4]) // native x86_64/arm64 byte order, never crosses the network
	ev.dport = binary.BigEndian.Uint16(raw[4:6])  // raw sockaddr_in.sin_port bytes: always network (big-endian) order
	copy(ev.daddr[:], raw[6:10])                  // raw sockaddr_in.sin_addr bytes, read octet-by-octet, no numeric byte-order question at all
	copy(ev.comm[:], raw[10:26])
	return ev, true
}

// resolveLLMHosts resolves each of hosts to its current A records, so a
// captured connection's raw destination IP can be matched back to the
// hostname a higher-level connector (detectors.ShadowAI) already knows how
// to reason about. Resolution failures are silently skipped: a captured
// flow to that provider still gets reported, just under its raw IP instead
// of a resolved hostname, which is strictly a display/matching
// degradation, never a dropped flow.
func resolveLLMHosts(hosts []string) map[string]string {
	out := make(map[string]string, len(hosts))
	for _, h := range hosts {
		addrs, err := net.LookupHost(h)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				out[ip.String()] = h
			}
		}
	}
	return out
}
