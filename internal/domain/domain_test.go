package domain

import "testing"

func TestPortablePaths(t *testing.T) {
	for _, p := range []string{"../.env", "a/../../x", "/etc/passwd", `C:\\secret`, "C:secret", `a\b`, "a//b", "a/./b", "CON", "a/NUL.txt", "LPT1.env", "a. ", "file:stream", "a\x00b", "a\nb", ".env/../secret", "a/*"} {
		if ValidatePath(p) == nil {
			t.Errorf("accepted unsafe path %q", p)
		}
	}
	for _, p := range []string{".env", "apps/web/.env.local", "a/b/.env.production", "dotenv-ü"} {
		if e := ValidatePath(p); e != nil {
			t.Errorf("rejected %q", p)
		}
	}
}
func TestConditions(t *testing.T) {
	for _, c := range []Condition{{Mode: IfETagMatch}, {Mode: CreateIfAbsent, ETag: "bad"}, {Mode: 99}} {
		if c.Validate() == nil {
			t.Fatal("accepted invalid condition")
		}
	}
	if !NewID().Valid() {
		t.Fatal("invalid generated ID")
	}
}
func FuzzPortablePath(f *testing.F) {
	for _, s := range []string{".env", "../.env", "C:secret", "a/.env"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if ValidatePath(p) == nil {
			if len(p) == 0 {
				t.Fatal("empty path accepted")
			}
		}
	})
}

func TestTrackedPathProtectsGitInternals(t *testing.T) {
	for _, p := range []string{".git/config", ".git/hooks/.env", "bin/executable", "config.json"} {
		if ValidateTrackedPath(p) == nil {
			t.Fatalf("accepted dangerous tracked path %q", p)
		}
	}
	if ValidateTrackedPath("apps/web/.env.local") != nil {
		t.Fatal("valid tracked path rejected")
	}
}
