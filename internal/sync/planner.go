// Package sync implements the pure, deterministic three-way state machine.
package sync

type Action string

const (
	Clean         Action = "clean"
	Upload        Action = "upload"
	Download      Action = "download"
	Conflict      Action = "conflict"
	Missing       Action = "missing"
	Unmapped      Action = "unmapped"
	Tombstone     Action = "tombstone"
	DeletePending Action = "delete_pending"
)
const Deleted = "deleted"

func Decide(base, local, remote string, explicitRemove bool) Action {
	if explicitRemove {
		if remote == Deleted {
			return Clean
		}
		if remote != "" && base != remote {
			return Conflict
		}
		return Tombstone
	}
	if local == "" {
		if remote == "" || remote == base {
			return Missing
		}
		if remote == Deleted {
			return Clean
		}
		return Download
	}
	if local == remote {
		return Clean
	}
	if remote == Deleted {
		if base == Deleted {
			return Upload
		}
		if base == local {
			return DeletePending
		}
		return Conflict
	}
	if remote == "" {
		if base == "" {
			return Upload
		}
		return Conflict
	}
	if base == "" {
		return Conflict
	}
	if local == base {
		return Download
	}
	if remote == base {
		return Upload
	}
	return Conflict
}
