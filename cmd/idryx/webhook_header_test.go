package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeHeaderFile writes content to a fresh file and then sets its mode
// exactly, because WriteFile's mode is masked by the umask.
func writeHeaderFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "webhook.headers")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// headerEndpoint answers every request 200 and keeps the headers of the last
// one. The mutex is there because the handler runs on the server's goroutine.
type headerEndpoint struct {
	mu    sync.Mutex
	calls int
	last  http.Header
}

func newHeaderEndpoint(t *testing.T) (*headerEndpoint, *httptest.Server) {
	t.Helper()
	e := &headerEndpoint{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.calls++
		e.last = r.Header.Clone()
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return e, srv
}

func (e *headerEndpoint) got() (int, http.Header) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls, e.last
}

// TestWebhookHeaderFileIsSentWithTheAlerts: a header file readable by its
// owner only is loaded and its headers go out with the webhook request.
func TestWebhookHeaderFileIsSentWithTheAlerts(t *testing.T) {
	path := writeHeaderFile(t, "Authorization: Bearer test-key\n", 0o600)
	ep, srv := newHeaderEndpoint(t)

	var err error
	captureStdout(t, func() {
		err = runDetect(detectArgsFor("-webhook", srv.URL, "-webhook-header-file", path))
	})
	if err != nil {
		t.Fatalf("runDetect: %v", err)
	}
	calls, h := ep.got()
	if calls == 0 {
		t.Fatal("expected the webhook to be called at least once")
	}
	if got := h.Get("Authorization"); got != "Bearer test-key" {
		t.Errorf("Authorization = %q, want the value from the header file", got)
	}
}

// TestHeaderFileReadableByOthersIsRefusedBeforeAnySend: group or other users
// can read the file, so the run refuses it, names the file and its mode,
// does not print the value, and sends nothing.
func TestHeaderFileReadableByOthersIsRefusedBeforeAnySend(t *testing.T) {
	path := writeHeaderFile(t, "Authorization: Bearer test-key\n", 0o644)
	ep, srv := newHeaderEndpoint(t)

	var err error
	captureStdout(t, func() {
		err = runDetect(detectArgsFor("-webhook", srv.URL, "-webhook-header-file", path))
	})
	if err == nil {
		t.Fatal("expected a refusal for a header file readable by other users")
	}
	if !strings.Contains(err.Error(), "0644") {
		t.Errorf("error %q does not name the file's mode 0644", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the file", err)
	}
	if strings.Contains(err.Error(), "test-key") {
		t.Errorf("error %q prints the header value", err)
	}
	if calls, _ := ep.got(); calls != 0 {
		t.Errorf("a refused header file still led to %d request(s)", calls)
	}
}

// TestHeaderFileRefusesAMalformedLineWithoutEchoingIt: a line with no colon
// is refused by its number, and the line itself, which may hold a secret, is
// not printed.
func TestHeaderFileRefusesAMalformedLineWithoutEchoingIt(t *testing.T) {
	const secret = "sekrit-without-a-colon"
	path := writeHeaderFile(t, "Authorization: Bearer test-key\n"+secret+"\n", 0o600)

	_, err := readHeaderFile(path)
	if err == nil {
		t.Fatal("expected a refusal for a line with no colon")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error %q does not name line 2", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error %q prints the malformed line", err)
	}
}

// TestEnvironmentNamesTheHeaderFile: with no header file flag, the environment
// variable names the file, and its headers go out.
func TestEnvironmentNamesTheHeaderFile(t *testing.T) {
	path := writeHeaderFile(t, "Authorization: Bearer env-key\n", 0o600)
	t.Setenv("IDRYX_WEBHOOK_HEADER_FILE", path)
	ep, srv := newHeaderEndpoint(t)

	var err error
	captureStdout(t, func() {
		err = runDetect(detectArgsFor("-webhook", srv.URL))
	})
	if err != nil {
		t.Fatalf("runDetect: %v", err)
	}
	calls, h := ep.got()
	if calls == 0 {
		t.Fatal("expected the webhook to be called at least once")
	}
	if got := h.Get("Authorization"); got != "Bearer env-key" {
		t.Errorf("Authorization = %q, want the value from the file the environment named", got)
	}
}

// TestCommandLineHeaderOverridesTheFile: when the file and the command line
// set the same name, the command line wins.
func TestCommandLineHeaderOverridesTheFile(t *testing.T) {
	path := writeHeaderFile(t, "X-Origin: from-file\n", 0o600)
	ep, srv := newHeaderEndpoint(t)

	var err error
	captureStdout(t, func() {
		err = runDetect(detectArgsFor("-webhook", srv.URL,
			"-webhook-header-file", path, "-webhook-header", "X-Origin: from-flag"))
	})
	if err != nil {
		t.Fatalf("runDetect: %v", err)
	}
	calls, h := ep.got()
	if calls == 0 {
		t.Fatal("expected the webhook to be called at least once")
	}
	if got := h.Get("X-Origin"); got != "from-flag" {
		t.Errorf("X-Origin = %q, want the command line value from-flag", got)
	}
}

// TestCredentialHeaderOnTheCommandLineIsNamedWithAWarning: a credential-looking
// header on the command line is still sent, and stderr gets one line naming
// it. The line must not print the value.
func TestCredentialHeaderOnTheCommandLineIsNamedWithAWarning(t *testing.T) {
	ep, srv := newHeaderEndpoint(t)

	var err error
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			err = runDetect(detectArgsFor("-webhook", srv.URL, "-webhook-header", "Authorization: Bearer cli-key"))
		})
	})
	if err != nil {
		t.Fatalf("runDetect: %v", err)
	}
	calls, h := ep.got()
	if calls == 0 {
		t.Fatal("expected the webhook to be called at least once")
	}
	if got := h.Get("Authorization"); got != "Bearer cli-key" {
		t.Errorf("Authorization = %q, want the command line header still sent", got)
	}
	var named []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(line, "Authorization") {
			named = append(named, line)
		}
		if strings.Contains(line, "cli-key") {
			t.Errorf("stderr prints the header value: %q", line)
		}
	}
	if len(named) != 1 {
		t.Errorf("stderr has %d line(s) naming Authorization, want exactly one warning line:\n%s", len(named), stderr)
	}
}

// TestOrdinaryHeaderOnTheCommandLineIsNotWarned: a header whose name is not
// credential-looking gets no warning. This is a negative control: it passes
// on the unfixed code too, because no warning existed.
func TestOrdinaryHeaderOnTheCommandLineIsNotWarned(t *testing.T) {
	var buf bytes.Buffer
	warnCredentialHeaders(&buf, headerList{"X-Origin": "https://idryx.internal:8443/detect"})
	if buf.Len() != 0 {
		t.Errorf("an ordinary header produced a warning: %q", buf.String())
	}
}

// TestCredentialLookingNamesAreRecognised: the name test is case-insensitive
// and covers the families the warning is for, and not the ordinary ones.
func TestCredentialLookingNamesAreRecognised(t *testing.T) {
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "cookie", "Cookie",
		"X-Api-Key", "X-Auth-Token", "X-Client-Secret", "x-api_key",
	} {
		if !isCredentialHeader(name) {
			t.Errorf("isCredentialHeader(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"Accept", "X-Origin", "Content-Type", "User-Agent"} {
		if isCredentialHeader(name) {
			t.Errorf("isCredentialHeader(%q) = true, want false", name)
		}
	}
}

// TestHeaderFileModeBoundary: group and other read bits refuse the file, the
// owner-only modes are read.
func TestHeaderFileModeBoundary(t *testing.T) {
	cases := []struct {
		mode    os.FileMode
		refused bool
	}{
		{0o600, false},
		{0o400, false},
		{0o640, true},
		{0o604, true},
		{0o644, true},
		{0o660, true},
	}
	for _, c := range cases {
		path := writeHeaderFile(t, "Authorization: Bearer k\n", c.mode)
		h, err := readHeaderFile(path)
		if c.refused {
			if err == nil {
				t.Errorf("mode %04o: read, want a refusal", c.mode)
			} else if want := fmt.Sprintf("%04o", c.mode); !strings.Contains(err.Error(), want) {
				t.Errorf("mode %04o: refusal %q does not name the mode %s", c.mode, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("mode %04o: %v, want it read", c.mode, err)
			continue
		}
		if h["Authorization"] != "Bearer k" {
			t.Errorf("mode %04o: headers %v, want the one Authorization header", c.mode, h)
		}
	}
}

// TestHeaderFileSkipsBlankAndCommentLinesAndKeepsColonsInValues: blank and
// comment lines are not headers, and only the first colon separates the name
// from the value.
func TestHeaderFileSkipsBlankAndCommentLinesAndKeepsColonsInValues(t *testing.T) {
	path := writeHeaderFile(t, "\n# the SIEM intake\nX-Origin: https://idryx.internal:8443/detect\n\n", 0o600)
	h, err := readHeaderFile(path)
	if err != nil {
		t.Fatalf("readHeaderFile: %v", err)
	}
	if len(h) != 1 || h["X-Origin"] != "https://idryx.internal:8443/detect" {
		t.Errorf("headers = %v, want only X-Origin with its full value", h)
	}
}

// TestHeaderFileMissingOrDirectoryIsAnError: a path that is not a regular file
// is refused, and so is one that does not exist.
func TestHeaderFileMissingOrDirectoryIsAnError(t *testing.T) {
	if _, err := readHeaderFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing header file was read without an error")
	}
	if _, err := readHeaderFile(t.TempDir()); err == nil {
		t.Error("a directory was read as a header file without an error")
	}
}
