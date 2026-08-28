// The declaration in components.json is only worth reading if this repository
// proves it, and proves it by RUNNING rather than by describing.
//
// estate-gates cannot do this. It has no Go toolchain, and building twenty-two
// repositories in its CI is a matrix it does not have. This repository already
// runs its suite on every push, so the marginal cost of a few process starts is
// seconds.
//
// What is proved here is exactly the `checked` bucket and the `pairs` list, and
// nothing else. The `declared` bucket is not asserted against anything, on
// purpose: a test that pretended to verify a sentence about purpose would be
// the failure this whole design exists to avoid.
package manifest

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// os/exec copies a process's output on its own goroutine, so reading what it
// has written while the process is still running is a data race and `-race`
// says so. The serve test deliberately never waits for the process, because the
// claim under test is that it does NOT exit, so the buffer has to be the safe
// thing rather than the timing.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type envVar struct {
	Required bool `json:"required"`
}

type component struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Checked struct {
		Package                        string            `json:"package"`
		Subcommand                     string            `json:"subcommand"`
		ListenDefault                  string            `json:"listen_default"`
		HealthPath                     string            `json:"health_path"`
		Env                            map[string]envVar `json:"env"`
		UnauthenticatedRead            bool              `json:"unauthenticated_read"`
		RefusesWithoutAnEventSource    int               `json:"refuses_without_an_event_source"`
		ExitsZeroWithNothingConfigured bool              `json:"exits_zero_with_nothing_configured"`
	} `json:"checked"`
}

type pair struct {
	IfSet        string `json:"if_set"`
	ThenRequired string `json:"then_required"`
	ExitCode     int    `json:"exit_code"`
}

type manifest struct {
	Schema     string      `json:"schema"`
	Repo       string      `json:"repo"`
	Components []component `json:"components"`
	Pairs      []pair      `json:"pairs"`
}

func root(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func load(t *testing.T) (manifest, string) {
	t.Helper()
	r := root(t)
	b, err := os.ReadFile(filepath.Join(r, "components.json"))
	if err != nil {
		t.Fatalf("reading components.json: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parsing components.json: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("components.json declares no component, so every test here measured nothing")
	}
	return m, r
}

// Built once per run rather than once per test: three of these need the binary
// and building it three times is thirty seconds of CI for nothing.
func build(t *testing.T, r, pkg string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "idryx")
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Dir = r
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, out)
	}
	return bin
}

func pick(t *testing.T, m manifest, class string) component {
	t.Helper()
	for _, c := range m.Components {
		if c.Class == class {
			return c
		}
	}
	t.Fatalf("components.json declares no %s, so this measured nothing", class)
	return component{}
}

// THE ONE THAT CLOSES THE HOLE, with the twist this repository adds: two
// components share one package, so the comparison is against the SET of
// declared packages rather than one per component.
func TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	list := exec.Command("go", "list", "-f", "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}", "./...")
	// Without this the command runs in THIS package's directory and `./...`
	// means this package alone. It then finds no main package, and the test
	// passes while measuring nothing.
	list.Dir = r
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	built := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			built[line] = true
		}
	}
	if len(built) == 0 {
		t.Fatal("go list found no main package in this repository, so this measured nothing")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		if c.Checked.Package == "" {
			t.Errorf("component %q declares no package", c.Name)
			continue
		}
		declared[c.Checked.Package] = true
	}
	for p := range built {
		if !declared[p] {
			t.Errorf("this repository builds %s and components.json does not declare it.\n"+
				"A component nobody declares is one no deployment can be asked to install.", p)
		}
	}
	for p := range declared {
		if !built[p] {
			t.Errorf("components.json declares %s and this repository does not build it", p)
		}
	}
}

// A declared subcommand is one the binary actually dispatches on.
//
// This is what makes `subcommand` a fact rather than a label: two components
// pointing at one package are only distinguishable by it, so a typo here would
// silently declare two copies of the same thing.
func TestEveryDeclaredSubcommandIsOneTheBinaryDispatchesOn(t *testing.T) {
	m, r := load(t)

	b, err := os.ReadFile(filepath.Join(r, "cmd", "idryx", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	// The dispatch is a plain `switch` over the first argument.
	known := map[string]bool{}
	for _, hit := range regexp.MustCompile(`(?m)^\tcase "([a-z-]+)":`).FindAllStringSubmatch(string(b), -1) {
		known[hit[1]] = true
	}
	if len(known) == 0 {
		t.Fatal("main.go no longer dispatches with a top-level `case \"...\":`, so this measured nothing")
	}

	checked := 0
	for _, c := range m.Components {
		if c.Checked.Subcommand == "" {
			continue
		}
		checked++
		if !known[c.Checked.Subcommand] {
			t.Errorf("components.json says %s runs `idryx %s` and main.go dispatches no such subcommand",
				c.Name, c.Checked.Subcommand)
		}
	}
	if checked == 0 {
		t.Fatal("no component declares a subcommand, so this measured nothing")
	}
}

// Every IDRYX_ name in non-test source, against every one declared.
//
// It reads STRING LITERALS rather than walking calls to os.Getenv, for the same
// reason its siblings do: a helper between the two hides the name from a reader
// that follows call sites. A name ending in `_` is a prefix fragment from a doc
// comment and not a variable.
func TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	name := regexp.MustCompile(`IDRYX_[A-Z0-9_]+`)
	inSource := map[string]bool{}
	err := filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range name.FindAllString(string(b), -1) {
			if !strings.HasSuffix(n, "_") {
				inSource[n] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if len(inSource) == 0 {
		t.Fatal("no IDRYX_ name found in any non-test .go file, so this measured nothing")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		for k := range c.Checked.Env {
			declared[k] = true
		}
	}
	var missing, extra []string
	for n := range inSource {
		if !declared[n] {
			missing = append(missing, n)
		}
	}
	for n := range declared {
		if !inSource[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, n := range missing {
		t.Errorf("the code reads %s and components.json does not declare it", n)
	}
	for _, n := range extra {
		t.Errorf("components.json declares %s and no non-test source reads it", n)
	}
}

// THE PAIR, WHICH `required: true/false` CANNOT SAY.
//
// IDRYX_TRUST_DOMAIN is required if and only if IDRYX_EVENTS is set. Proved the
// only way it can be: run the binary three ways and compare the exit codes.
func TestAConditionallyRequiredVariableIsRequiredExactlyWhenItsPartnerIsSet(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	m, r := load(t)
	if len(m.Pairs) == 0 {
		t.Fatal("components.json records no pair, so this measured nothing")
	}
	tool := pick(t, m, "tool")
	bin := build(t, r, tool.Checked.Package)
	log := writeOneEvent(t)

	for _, p := range m.Pairs {
		run := func(env []string) int {
			cmd := exec.Command(bin, tool.Checked.Subcommand, "--load", "tokenfuse:"+log)
			cmd.Env = env
			err := cmd.Run()
			if err == nil {
				return 0
			}
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return exit.ExitCode()
			}
			t.Fatalf("running it: %v", err)
			return -1
		}

		if got := run(nil); got != 0 {
			t.Errorf("with neither %s nor %s set it exited %d; the pair only binds when %s is set",
				p.IfSet, p.ThenRequired, got, p.IfSet)
		}
		alone := run([]string{p.IfSet + "=" + filepath.Join(t.TempDir(), "out.ndjson")})
		if alone != p.ExitCode {
			t.Errorf("with %s set and %s missing it exited %d; components.json says %d",
				p.IfSet, p.ThenRequired, alone, p.ExitCode)
		}
		both := run([]string{
			p.IfSet + "=" + filepath.Join(t.TempDir(), "out.ndjson"),
			p.ThenRequired + "=meridian.example",
		})
		if both != 0 {
			t.Errorf("with both %s and %s set it exited %d, so the pair is not what makes it refuse",
				p.IfSet, p.ThenRequired, both)
		}
	}
}

// The tool half: it runs and exits, and exits ZERO with nothing configured.
func TestTheToolExitsZeroWithNothingConfigured(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	m, r := load(t)
	tool := pick(t, m, "tool")
	if !tool.Checked.ExitsZeroWithNothingConfigured {
		t.Skip("the manifest makes no such claim")
	}
	cmd := exec.Command(build(t, r, tool.Checked.Package), tool.Checked.Subcommand,
		"--load", "tokenfuse:"+writeOneEvent(t))
	cmd.Env = []string{}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("`idryx %s` with an empty environment failed: %v\n%s",
			tool.Checked.Subcommand, err, out)
	}
}

// AND THE HALF NO CENTRAL FILE COULD EVER DO: serve it.
//
// Two claims, and the second is the one worth having. It refuses without an
// event source, with the declared exit code. And once up, /healthz AND a data
// route both answer 200 with NO credential: nothing here authenticates, which
// is the opposite of wardryx next door, where every /v1 route answers 401
// without a key. Both are correct for what they are and neither is guessable
// from source.
func TestItRefusesWithoutAnEventSourceAndThenServesWithoutAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	m, r := load(t)
	svc := pick(t, m, "service")
	bin := build(t, r, svc.Checked.Package)

	if want := svc.Checked.RefusesWithoutAnEventSource; want != 0 {
		cmd := exec.Command(bin, svc.Checked.Subcommand, "--addr", "127.0.0.1:0")
		cmd.Env = []string{}
		err := cmd.Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Errorf("with no event source it did not exit with a status: %v", err)
		} else if exit.ExitCode() != want {
			t.Errorf("with no event source it exited %d; components.json says %d",
				exit.ExitCode(), want)
		}
	}

	// A port the OS picks, so a developer already running idryx does not make
	// this fail for a reason that is not a finding. The DEFAULT is a separate
	// claim and is checked below without binding anything.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("releasing the reserved port: %v", err)
	}

	cmd := exec.Command(bin, svc.Checked.Subcommand, "--addr", addr,
		"--load", "tokenfuse:"+writeOneEvent(t))
	cmd.Env = []string{}
	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting it: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	up := false
	for i := 0; i < 60; i++ {
		resp, err := client.Get("http://" + addr + svc.Checked.HealthPath)
		if err == nil {
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == http.StatusOK {
				up = true
				break
			}
			t.Fatalf("%s answered %d with no credential", svc.Checked.HealthPath, code)
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if !up {
		t.Fatalf("it never answered %s: %v\nits output was:\n%s",
			svc.Checked.HealthPath, lastErr, out.String())
	}

	if !svc.Checked.UnauthenticatedRead {
		return
	}
	// A DATA route, not the liveness one. /healthz answering without a
	// credential is ordinary; the claim being proved is that the identity graph
	// does too.
	resp, err := client.Get("http://" + addr + "/api/identities")
	if err != nil {
		t.Fatalf("GET /api/identities: %v", err)
	}
	code := resp.StatusCode
	_ = resp.Body.Close()
	if code != http.StatusOK {
		t.Errorf("GET /api/identities answered %d with no credential.\n"+
			"components.json declares this service as unauthenticated_read, and if that "+
			"has stopped being true the manifest is what has to change, along with every "+
			"deployment that relied on it.", code)
	}
}

// The declared listen default is the constant `serve` actually falls back to.
func TestTheDeclaredListenDefaultIsTheOneServeFallsBackTo(t *testing.T) {
	m, r := load(t)
	b, err := os.ReadFile(filepath.Join(r, "cmd", "idryx", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	found := regexp.MustCompile(`defaultServeAddr\s*=\s*"([^"]*)"`).FindStringSubmatch(string(b))
	if found == nil {
		t.Fatal("main.go no longer defines defaultServeAddr, so this measured nothing")
	}
	if got := pick(t, m, "service").Checked.ListenDefault; got != found[1] {
		t.Errorf("components.json says the default listen address is %q; main.go says %q",
			got, found[1])
	}
}

func writeOneEvent(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "events.ndjson")
	line := `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-28T09:00:00.000Z",` +
		`"source":"tokenfuse","type":"budget_exhausted","severity":"high",` +
		`"agent_id":"agent://meridian.example/sre/rca","run_id":"run-1"}` + "\n"
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatalf("writing the event log: %v", err)
	}
	return p
}
