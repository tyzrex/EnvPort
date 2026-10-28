// Package domain contains provider-independent identities, contracts and errors.
package domain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

type ID string

func NewID() ID {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system randomness unavailable")
	}
	return ID(hex.EncodeToString(b[:]))
}

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var reservedDevicePattern = regexp.MustCompile(`^(COM|LPT)[1-9]$`)

func (id ID) Valid() bool { return idPattern.MatchString(string(id)) }

var (
	ErrNotFound     = errors.New("not found")
	ErrPrecondition = errors.New("storage precondition failed; fetch current state and replan")
	ErrConflict     = errors.New("conflicting changes require explicit resolution")
	ErrUnsafePath   = errors.New("unsafe path")
	ErrCorrupt      = errors.New("invalid or unauthenticated vault data")
	ErrRollback     = errors.New("remote history does not descend from trusted checkpoint")
)

const MaxFileSize int64 = 8 << 20
const MaxObjectSize int64 = 16 << 20
const MaxManifestFiles = 10000

type PutMode int

const (
	CreateIfAbsent PutMode = iota
	IfETagMatch
	Unconditional
)

type Condition struct {
	Mode PutMode
	ETag string
}

func (c Condition) Validate() error {
	if c.Mode < CreateIfAbsent || c.Mode > Unconditional || (c.Mode == IfETagMatch) != (c.ETag != "") {
		return errors.New("invalid write condition")
	}
	return nil
}

type ObjectInfo struct {
	Key  string `json:"key"`
	ETag string `json:"etag"`
	Size int64  `json:"size"`
}
type Page struct {
	Objects []ObjectInfo `json:"objects"`
	Cursor  string       `json:"cursor,omitempty"`
}
type Capabilities struct {
	ConditionalCreate  bool  `json:"conditional_create"`
	ConditionalReplace bool  `json:"conditional_replace"`
	Verified           bool  `json:"verified"`
	MaxObjectSize      int64 `json:"max_object_size"`
}
type ObjectStore interface {
	Put(context.Context, string, io.Reader, Condition) (ObjectInfo, error)
	Get(context.Context, string) (io.ReadCloser, ObjectInfo, error)
	Head(context.Context, string) (ObjectInfo, error)
	List(context.Context, string, string, int) (Page, error)
	Delete(context.Context, string) error
	Capabilities() Capabilities
	Close() error
}
type CredentialStore interface {
	Load(context.Context, ID) ([]byte, error)
	Save(context.Context, ID, []byte) error
}
type ProjectMapper interface {
	Map(context.Context, ID, string) error
}

// ValidatePath is deliberately portable: a vault written on Unix must be safe on Windows.
func ValidatePath(p string) error {
	if p == "" || len(p) > 1024 || !utf8.ValidString(p) || strings.ContainsAny(p, "\\:\x00\r\n") || strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return ErrUnsafePath
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." || part == "" || strings.TrimRight(part, " .") != part {
			return ErrUnsafePath
		}
		for _, r := range part {
			if r < 32 || r == 127 || strings.ContainsRune(`<>"|?*`, r) {
				return ErrUnsafePath
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || reservedDevicePattern.MatchString(base) {
			return ErrUnsafePath
		}
	}
	return nil
}
func ValidateKey(k string) error {
	if len(k) > 2048 {
		return ErrUnsafePath
	}
	return ValidatePath(k)
}

// ValidateTrackedPath restricts v1 restores to environment files outside Git internals.
func ValidateTrackedPath(p string) error {
	if e := ValidatePath(p); e != nil {
		return e
	}
	for _, part := range strings.Split(p, "/") {
		if strings.EqualFold(part, ".git") {
			return ErrUnsafePath
		}
	}
	name := path.Base(p)
	if name != ".env" && !strings.HasPrefix(name, ".env.") {
		return ErrUnsafePath
	}
	return nil
}
