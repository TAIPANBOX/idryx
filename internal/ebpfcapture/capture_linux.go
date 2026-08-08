//go:build linux

package ebpfcapture

import (
	"context"
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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type conn_event -type skipped_counts -cc clang bpf bpf/connect.c -- -g -O2 -I bpf
//
// AFTER REGENERATING, PUT THE `linux &&` BACK. bpf2go tags bpf_bpfel.go and
// bpf_bpfeb.go by ARCHITECTURE only, with no OS constraint, and it has no flag
// to add one. Without `linux &&` those files compile on darwin and windows too,
// which drags all 19 cilium/ebpf packages into the dependency graph of a build
// that can never use them. Invariant 4 says the eBPF layer is optional; that is
// the line that makes it true. `scripts/ebpf-optional.sh` fails the moment it
// is gone, so this is a visible debt rather than a silent one.

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
// Duration elapses (whichever first), and returns every captured flow together
// with what it deliberately did not capture.
//
// The second return value is not diagnostics. AGENTS.md invariant 4 requires
// idryx to say what it could not observe rather than present a partial graph as
// a complete one, and an empty flow list has three meanings without it: nothing
// connected, everything connected over a family this sensor ignores, or the
// ring buffer filled and real evidence went on the floor.
//
// Requires root (or CAP_BPF+CAP_PERFMON); returns a clear error otherwise
// rather than a confusing EPERM three calls deep into the kernel.
func Run(ctx context.Context, opts Options) ([]Flow, SkippedCounts, error) {
	var skipped SkippedCounts
	if os.Geteuid() != 0 {
		return nil, skipped, fmt.Errorf("ebpfcapture: requires root (or CAP_BPF+CAP_PERFMON); re-run with sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, skipped, fmt.Errorf("ebpfcapture: remove memlock rlimit: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, skipped, fmt.Errorf("ebpfcapture: load eBPF objects (need root + a BTF-enabled kernel, see /sys/kernel/btf/vmlinux): %w", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.OnConnect, nil)
	if err != nil {
		return nil, skipped, fmt.Errorf("ebpfcapture: attach sys_enter_connect: %w", err)
	}
	defer tp.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, skipped, fmt.Errorf("ebpfcapture: open ring buffer: %w", err)
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
			return flows, readSkipped(&objs), fmt.Errorf("ebpfcapture: read ring buffer: %w", err)
		}
		ev, ok := decodeConnEvent(record.RawSample)
		if !ok || ev.dport == 0 || ev.pid == selfPID {
			continue
		}
		ip := ev.IP()
		if ip == nil {
			// A family this decoder was not written against. connect.c only
			// ever writes 4 or 6, so this is a connect.c/decode.go mismatch
			// rather than traffic, and reporting an address from a layout we
			// do not recognise would be worse than reporting nothing.
			continue
		}
		if ip.IsLoopback() && !isLocalModelPort(ev.dport) {
			continue // local chatter, not a model port
		}
		comm := strings.TrimRight(string(ev.comm[:]), "\x00")
		f := Flow{Time: time.Now().UTC(), Identity: Identity(comm), Destination: destination(ip, ev.dport, llmIPs), PID: ev.pid}
		flows = append(flows, f)
		if opts.OnFlow != nil {
			opts.OnFlow(f)
		}
	}
	return flows, readSkipped(&objs), nil
}

// readSkipped reads the per-reason counters connect.c maintained during the
// capture. A failure here returns zeros rather than an error: the flows are
// real either way, and losing the capture over an unreadable counter would
// trade the thing this sensor exists for against the thing that describes it.
// Zeros in that case are indistinguishable from a clean run, which is the one
// dishonesty this function cannot avoid and is why it is named here.
func readSkipped(objs *bpfObjects) SkippedCounts {
	var raw bpfSkippedCounts
	if err := objs.Skipped.Lookup(uint32(0), &raw); err != nil {
		return SkippedCounts{}
	}
	return SkippedCounts{
		OtherFamily: raw.OtherFamily,
		Unreadable:  raw.Unreadable,
		RingbufFull: raw.RingbufFull,
	}
}

// resolveLLMHosts resolves each of hosts to its current addresses, so a
// captured connection's raw destination IP can be matched back to the
// hostname a higher-level connector (detectors.ShadowAI) already knows how
// to reason about. Resolution failures are silently skipped: a captured
// flow to that provider still gets reported, just under its raw IP instead
// of a resolved hostname, which is strictly a display/matching
// degradation, never a dropped flow.
//
// Both families, since the sensor observes both. It used to keep only the A
// records (`ip.To4() != nil`), so a host reaching api.openai.com over IPv6 was
// captured and then reported under a bare address that matched nothing: the
// flow was there and the shadow_ai finding it should have produced was not.
// The map is keyed on net.IP.String(), which is canonical for both families,
// so no normalisation is needed on either side.
func resolveLLMHosts(hosts []string) map[string]string {
	out := make(map[string]string, len(hosts))
	for _, h := range hosts {
		addrs, err := net.LookupHost(h)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				out[ip.String()] = h
			}
		}
	}
	return out
}
