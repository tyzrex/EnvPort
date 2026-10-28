package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func run(t *testing.T, home string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := New()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--home", home, "--json"}, args...))
	e := cmd.Execute()
	return out.Bytes(), e
}
func TestHelpScanAndVersionNeedNoState(t *testing.T) {
	home := filepath.Join(t.TempDir(), "not-created")
	for _, args := range [][]string{{"--help"}, {"version"}, {"scan", t.TempDir()}} {
		if _, e := run(t, home, args...); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := os.Stat(home); !os.IsNotExist(e) {
		t.Fatal("read-only command initialized state")
	}
}
func TestInitAndValidation(t *testing.T) {
	home := filepath.Join(t.TempDir(), "state")
	out, e := run(t, home, "init")
	if e != nil {
		t.Fatal(e)
	}
	if !json.Valid(out) {
		t.Fatal("invalid machine JSON")
	}
	if _, e = run(t, home, "scan"); e == nil {
		t.Fatal("missing roots accepted")
	}
	if _, e = run(t, home, "storage", "add", "filesystem", "--name", "invalid/path", "--path", t.TempDir()); e == nil {
		t.Fatal("invalid profile accepted")
	}
	out, e = run(t, home, "storage", "test", "local")
	if e != nil || !json.Valid(out) {
		t.Fatal("local probe failed")
	}
}

func TestLANCommandsAndSetupAreExplicit(t *testing.T) {
	home := filepath.Join(t.TempDir(), "state")
	if _, err := run(t, home, "init", "--lan"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, home, "storage", "list")
	if err != nil || string(bytes.TrimSpace(out)) != "[]" {
		t.Fatal("LAN init created an implicit local fallback")
	}
	for _, args := range [][]string{{"init", "--lan", "--offline"}, {"storage", "add", "lan", "--name", "home"}, {"serve", "--data", filepath.Join(t.TempDir(), "absent"), "init", "--endpoint", "https://8.8.8.8:7443"}, {"serve", "--no-network"}} {
		if _, err = run(t, home, args...); err == nil {
			t.Fatal("unsafe or incomplete LAN invocation accepted")
		}
	}
	hostHome := filepath.Join(t.TempDir(), "host-home")
	if _, err = run(t, hostHome, "serve", "inspect"); err == nil {
		t.Fatal("uninitialized host inspected successfully")
	}
	if _, err = os.Stat(hostHome); !os.IsNotExist(err) {
		t.Fatal("server-only command initialized client state")
	}
}
