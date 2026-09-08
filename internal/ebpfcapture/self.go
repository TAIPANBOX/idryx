package ebpfcapture

// procPidInitIno is the inode of the initial PID namespace's /proc/self/ns/pid
// (PROC_PID_INIT_INO in include/linux/proc_ns.h), fixed by the kernel. A sensor
// whose namespace inode is this one runs on the host, where /proc addresses
// every task by the kernel's own pid; any other value means a nested namespace.
const procPidInitIno = 0xEFFFFFFC

// isSelf reports whether a captured connect() was made by this sensor.
//
// Decided on the tgid as the sensor's own PID namespace numbers it, which the
// program computes with bpf_get_ns_current_pid_tgid() for tasks in that
// namespace and leaves 0 for every other task. The kernel's pid is never
// consulted: inside a container it belongs to the initial namespace while
// os.Getpid() belongs to this one, so the two never agree for us and can agree
// by coincidence for a foreign task (host pid 7 is not us because we are pid 7
// in here). Measured 2026-09-08: deciding on the raw pid, the sensor reported
// 16 of its own 21 flows from a container (TAIPANBOX/idryx#66).
func isSelf(ev decodedConnEvent, selfPID uint32) bool {
	return ev.nsTgid != 0 && ev.nsTgid == selfPID
}

// procPIDFor is the pid under which this sensor's /proc can address the
// connecting process: the kernel's pid when the sensor runs in the initial
// namespace, where /proc sees everything; the namespaced tgid otherwise; and 0
// for a task from another namespace, which this /proc cannot address at all
// and which claimedAgentURI reports as "not declared".
func procPIDFor(ev decodedConnEvent, inInitPidNS bool) uint32 {
	if inInitPidNS {
		return ev.pid
	}
	return ev.nsTgid
}
