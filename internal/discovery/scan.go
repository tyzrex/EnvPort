// Package discovery scans only explicit roots, without reading secret contents or following symlinks.
package discovery

import (
	"context"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Candidate struct {
	Root     string `json:"root"`
	Path     string `json:"path"`
	Identity string `json:"identity,omitempty"`
	Size     int64  `json:"size"`
}
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}
type Result struct {
	Files   []Candidate `json:"files"`
	Skipped []Skip      `json:"skipped"`
}

var excluded = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, ".next": true, ".cache": true, ".venv": true, "venv": true, "__pycache__": true, ".envport": true, "target": true}

func IsEnv(name string) bool {
	if name != ".env" && !strings.HasPrefix(name, ".env.") {
		return false
	}
	for _, s := range []string{"example", "sample", "template"} {
		for _, part := range strings.Split(name, ".") {
			if strings.EqualFold(part, s) {
				return false
			}
		}
	}
	return true
}
func Scan(ctx context.Context, roots []string) (Result, error) {
	r := Result{Files: []Candidate{}, Skipped: []Skip{}}
	if len(roots) == 0 {
		return r, errors.New("provide explicit scan roots")
	}
	seen := map[string]bool{}
	for _, root := range roots {
		abs, e := filepath.Abs(root)
		if e != nil {
			return r, e
		}
		if e = CheckRoot(abs); e != nil {
			return r, e
		}
		e = filepath.WalkDir(abs, func(p string, d fs.DirEntry, walkErr error) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if walkErr != nil {
				r.Skipped = append(r.Skipped, Skip{p, "unreadable path"})
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				r.Skipped = append(r.Skipped, Skip{p, "symlink"})
				return nil
			}
			if d.IsDir() {
				rel, _ := filepath.Rel(abs, p)
				if (p != abs && excluded[d.Name()]) || len(strings.Split(rel, string(filepath.Separator))) > 64 {
					return fs.SkipDir
				}
				return nil
			}
			if !IsEnv(d.Name()) || !d.Type().IsRegular() || seen[p] {
				return nil
			}
			info, e := d.Info()
			if e != nil || info.Size() > domain.MaxFileSize {
				r.Skipped = append(r.Skipped, Skip{p, "unreadable or size limit"})
				return nil
			}
			project := ProjectRoot(p, abs)
			rel, e := filepath.Rel(project, p)
			if e != nil {
				return e
			}
			rel = filepath.ToSlash(rel)
			if domain.ValidatePath(rel) != nil {
				r.Skipped = append(r.Skipped, Skip{p, "nonportable path"})
				return nil
			}
			identity, e := Identity(ctx, project)
			if e != nil {
				r.Skipped = append(r.Skipped, Skip{project, "ambiguous or unsupported Git remotes; explicitly map identity"})
			}
			r.Files = append(r.Files, Candidate{project, rel, identity, info.Size()})
			seen[p] = true
			return nil
		})
		if e != nil {
			return r, e
		}
	}
	sort.Slice(r.Files, func(i, j int) bool {
		if r.Files[i].Root == r.Files[j].Root {
			return r.Files[i].Path < r.Files[j].Path
		}
		return r.Files[i].Root < r.Files[j].Root
	})
	return r, nil
}
func CheckRoot(root string) error {
	abs, e := filepath.Abs(root)
	if e != nil {
		return domain.ErrUnsafePath
	}
	volume := filepath.VolumeName(abs)
	current := volume + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		i, e := os.Lstat(current)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return domain.ErrUnsafePath
		}
	}
	return nil
}
func ProjectRoot(file, fallback string) string {
	p := filepath.Dir(file)
	for {
		if i, e := os.Lstat(filepath.Join(p, ".git")); e == nil && i.Mode()&os.ModeSymlink == 0 && (i.IsDir() || i.Mode().IsRegular()) {
			return p
		}
		// The explicit root is the authority boundary, even if an ancestor has .git metadata.
		if p == fallback {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	return fallback
}
func Identity(ctx context.Context, root string) (string, error) {
	marker, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil {
		return "", nil
	}
	if marker.Mode()&os.ModeSymlink != 0 || (!marker.IsDir() && !marker.Mode().IsRegular()) {
		return "", errors.New("unsafe Git metadata marker")
	}
	cmd := exec.CommandContext(ctx, "git", "-C", root, "config", "--local", "--get-regexp", `^remote\..*\.url$`)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0")
	out, e := cmd.Output()
	if e != nil {
		return "", nil
	}
	values := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			return "", errors.New("invalid Git remote")
		}
		id, e := CanonicalRemote(parts[1])
		if e != nil {
			return "", e
		}
		values[id] = true
	}
	if len(values) > 1 {
		return "", errors.New("multiple distinct Git remotes")
	}
	for v := range values {
		return v, nil
	}
	return "", nil
}
func CanonicalRemote(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("invalid Git remote")
	}
	if !strings.Contains(raw, "://") {
		if i := strings.Index(raw, ":"); i > 0 && !strings.Contains(raw[:i], "/") {
			host := raw[:i]
			if j := strings.LastIndex(host, "@"); j >= 0 {
				host = host[j+1:]
			}
			raw = "ssh://" + host + "/" + raw[i+1:]
		} else {
			return "", errors.New("local Git remotes require explicit mapping")
		}
	}
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "ssh" && u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "git") {
		return "", errors.New("unsupported Git remote")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" && !((u.Scheme == "ssh" && port == "22") || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80")) {
		host += ":" + port
	}
	p := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	if p == "" || domain.ValidatePath(p) != nil {
		return "", errors.New("invalid Git remote path")
	}
	return host + "/" + p, nil
}

// FindRepositories discovers Git markers without executing repository hooks or network commands.
func FindRepositories(ctx context.Context, roots []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, root := range roots {
		abs, e := filepath.Abs(root)
		if e != nil {
			return nil, e
		}
		if e = CheckRoot(abs); e != nil {
			return nil, e
		}
		e = filepath.WalkDir(abs, func(p string, d fs.DirEntry, walkErr error) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if walkErr != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if d.Name() == ".git" {
				parent := filepath.Dir(p)
				if !seen[parent] {
					out = append(out, parent)
					seen[parent] = true
				}
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				rel, _ := filepath.Rel(abs, p)
				if (p != abs && excluded[d.Name()]) || len(strings.Split(rel, string(filepath.Separator))) > 64 {
					return fs.SkipDir
				}
			}
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	sort.Strings(out)
	return out, nil
}
