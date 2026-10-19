package main

import (
	"os"
	"testing"
)

// The owner rule is tested with an injected stat and an injected uid, so every case
// runs unprivileged. The rule is PostgreSQL's rule for the private key a server loads
// (libpq-ssl docs, section 32.19.2; check_ssl_key_file_permissions in
// src/backend/libpq/be-secure-common.c).

const (
	ownerThisUser = 501 // the uid the process runs as, injected
	ownerAnother  = 502
	ownerRoot     = 0
)

func ownerFile(mode os.FileMode, uid int) headerFileStat {
	return headerFileStat{Mode: mode, UID: uid, Regular: true}
}

func TestOwnerRuleOwnedByThisUserAt0600IsAccepted(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := headerFileRefusal("linux", "h", ownerFile(mode, ownerThisUser), ownerThisUser); err != nil {
			t.Errorf("owned by this user, mode %04o: refused (%v), want accepted", mode, err)
		}
	}
}

func TestOwnerRuleOwnedByThisUserAt0640IsRefused(t *testing.T) {
	if err := headerFileRefusal("linux", "h", ownerFile(0o640, ownerThisUser), ownerThisUser); err == nil {
		t.Error("owned by this user, mode 0640: accepted, want refused: a file the user owns must be 0600 or stricter")
	}
}

func TestOwnerRuleOwnedByRootAt0440IsAccepted(t *testing.T) {
	if err := headerFileRefusal("linux", "h", ownerFile(0o440, ownerRoot), ownerThisUser); err != nil {
		t.Errorf("owned by root, mode 0440: refused (%v), want accepted", err)
	}
}

func TestOwnerRuleOwnedByRootAt0640IsAccepted(t *testing.T) {
	if err := headerFileRefusal("linux", "h", ownerFile(0o640, ownerRoot), ownerThisUser); err != nil {
		t.Errorf("owned by root, mode 0640: refused (%v), want accepted", err)
	}
}

func TestOwnerRuleOwnedByRootAt0660IsRefused(t *testing.T) {
	if err := headerFileRefusal("linux", "h", ownerFile(0o660, ownerRoot), ownerThisUser); err == nil {
		t.Error("owned by root, mode 0660: accepted, want refused: group write is never allowed")
	}
}

func TestOwnerRuleOwnedByAnotherUserIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := headerFileRefusal("linux", "h", ownerFile(mode, ownerAnother), ownerThisUser); err == nil {
			t.Errorf("owned by uid %d, mode %04o: accepted, want refused: the owner must be this user or root", ownerAnother, mode)
		}
	}
}

func TestOwnerRuleAnyOtherReadBitIsRefused(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		uid  int
	}{
		{0o604, ownerThisUser},
		{0o644, ownerRoot},
		{0o606, ownerThisUser},
		{0o445, ownerRoot},
	}
	for _, c := range cases {
		if err := headerFileRefusal("linux", "h", ownerFile(c.mode, c.uid), ownerThisUser); err == nil {
			t.Errorf("owned by uid %d, mode %04o: accepted, want refused: other users can read it", c.uid, c.mode)
		}
	}
}

func TestOwnerRuleNonRegularFileIsRefused(t *testing.T) {
	dir := headerFileStat{Mode: os.ModeDir | 0o700, UID: ownerThisUser, Regular: false}
	if err := headerFileRefusal("linux", "h", dir, ownerThisUser); err == nil {
		t.Error("a directory: accepted, want refused")
	}
}

func TestOwnerRuleWindowsSkipsTheModeAndOwnerChecks(t *testing.T) {
	if err := headerFileRefusal("windows", "h", ownerFile(0o644, ownerAnother), ownerThisUser); err != nil {
		t.Errorf("windows, mode 0644 owned by another uid: refused (%v), want the named skip", err)
	}
	dir := headerFileStat{Mode: os.ModeDir | 0o700, UID: -1, Regular: false}
	if err := headerFileRefusal("windows", "h", dir, ownerThisUser); err == nil {
		t.Error("windows, a directory: accepted, want refused: the regular-file rule applies on every OS")
	}
}

func TestOwnerRuleAsRootTheOwnerRuleComesFirst(t *testing.T) {
	if err := headerFileRefusal("linux", "h", ownerFile(0o640, ownerRoot), ownerRoot); err == nil {
		t.Error("run as root, a root-owned 0640 file: accepted, want refused: judged as owned by this user, which needs 0600")
	}
}
