package selfupdate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// State keeps what an updater must remember between runs. It never holds
// rules or decisions: those always come from the current manifest.
type State interface {
	// Update reads, changes and writes the state under a lock. Nothing is
	// written when fn returns an error, which Update returns.
	Update(ctx context.Context, fn func(*StateData) error) error
	// Load reads the state. No state yet gives the zero value.
	Load(ctx context.Context) (StateData, error)
}

// FailedEdge remembers that an update from one version to another failed.
type FailedEdge struct {
	// At is when it last failed; the wait before a retry counts from here.
	// Unused if Rejected.
	At time.Time `json:"at,omitzero"`
	// From, To and Digest name the edge; a new artifact makes the record void.
	From   string `json:"from"`
	To     string `json:"to"`
	Digest string `json:"digest"`
	// Failures counts failures in a row.
	Failures int `json:"failures,omitempty"`
	// Rejected says the new version refused From: retrying cannot help, so
	// the record does not expire.
	Rejected bool `json:"rejected,omitempty"`
}

// Handoff remembers an update handed to an installer outside this process.
type Handoff struct {
	// At is when it was handed over.
	At time.Time `json:"at"`
	// From, To and Digest name the edge.
	From   string `json:"from"`
	To     string `json:"to"`
	Digest string `json:"digest"`
	// Done says an installer finished this update and the new version has yet
	// to run. Used in [StateData].Attempt only.
	Done bool `json:"done,omitempty"`
}

// StateData is the content of a [State].
type StateData struct {
	// Handoff is the update awaiting [ConfirmHandoff], if any.
	Handoff *Handoff `json:"handoff,omitempty"`
	// Attempt is the update applied last and not yet known to have held.
	Attempt *Handoff `json:"attempt,omitempty"`
	// extra keeps fields of newer versions.
	extra map[string]json.RawMessage
	// Hash identifies the manifest of Serial, in hex.
	Hash string `json:"hash,omitempty"`
	// InstallID places this installation in rollouts; it is never reported.
	InstallID string `json:"install_id,omitempty"`
	// Failed lists failed edges.
	Failed []FailedEdge `json:"failed,omitempty"`
	// Downgraded lists versions left by a downgrade.
	Downgraded []string `json:"downgraded,omitempty"`
	// Serial is the highest manifest serial seen.
	Serial uint64 `json:"serial,omitempty"`
}

// MarshalJSON implements [json.Marshaler], keeping unknown fields.
func (d *StateData) MarshalJSON() ([]byte, error) {
	type plain StateData
	known, err := json.Marshal(plain(*d))
	if err != nil {
		return nil, err
	}
	if len(d.extra) == 0 {
		return known, nil
	}
	all := map[string]json.RawMessage{}
	maps.Copy(all, d.extra)
	if err := json.Unmarshal(known, &all); err != nil {
		return nil, err
	}
	return json.Marshal(all)
}

// UnmarshalJSON implements [json.Unmarshaler], keeping unknown fields.
func (d *StateData) UnmarshalJSON(data []byte) error {
	type plain StateData
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for _, k := range []string{"handoff", "attempt", "hash", "install_id", "failed", "downgraded", "serial"} {
		delete(all, k)
	}
	*d = StateData(p)
	d.extra = all
	return nil
}

// Advance records a manifest as seen. A lower serial, or the same serial with
// other content, fails with [ErrStaleManifest].
func (d *StateData) Advance(serial uint64, hash [sha256.Size]byte) error {
	h := hex.EncodeToString(hash[:])
	switch {
	case serial < d.Serial:
		return fmt.Errorf("%w: serial %d, seen %d", ErrStaleManifest, serial, d.Serial)
	case serial == d.Serial && d.Hash != "" && d.Hash != h:
		return fmt.Errorf("%w: serial %d has other content", ErrStaleManifest, serial)
	}
	d.Serial, d.Hash = serial, h
	return nil
}

type fileState struct{ path string }

// FileState keeps the state in a file. A damaged file counts as a first run,
// since the worst this can cause is accepting an older manifest once.
func FileState(path string) State { return fileState{path: path} }

func (s fileState) read() (StateData, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return StateData{}, nil
	}
	if err != nil {
		return StateData{}, err
	}
	var d StateData
	if json.Unmarshal(data, &d) != nil {
		return StateData{}, nil
	}
	return d, nil
}

// Load implements [State]. Writes replace the file atomically, so it needs no
// lock.
func (s fileState) Load(context.Context) (StateData, error) { return s.read() }

// Update implements [State].
func (s fileState) Update(ctx context.Context, fn func(*StateData) error) error {
	l, err := lockFile(ctx, s.path+".lock")
	if err != nil {
		return err
	}
	defer l.unlock()
	d, err := s.read()
	if err != nil {
		return err
	}
	if err := fn(&d); err != nil {
		return err
	}
	data, err := json.Marshal(&d)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := writeSynced(tmp, data); err != nil {
		return err
	}
	if err := (Journal{}).rename(tmp, s.path); err != nil {
		return errors.Join(err, removeIfExists(tmp))
	}
	return syncDir(filepath.Dir(s.path))
}

// ensureInstallID draws the identifier on first use, so that a read-only run
// never draws one that it cannot keep.
func (d *StateData) ensureInstallID() {
	if d.InstallID == "" {
		d.InstallID = rand.Text()
	}
}

// ConfirmHandoff tells the state that a handed-off update finished. The new
// version calls it after it took over.
func ConfirmHandoff(ctx context.Context, s State) error {
	return s.Update(ctx, func(d *StateData) error {
		d.Handoff = nil
		return nil
	})
}

// ImportState takes over a snapshot from [ActionContext].StateSnapshot, so an
// installation in a new layout keeps its serial and rollout place. It only
// moves the serial up.
func ImportState(ctx context.Context, s State, snapshot []byte) error {
	var from StateData
	if err := json.Unmarshal(snapshot, &from); err != nil {
		return fmt.Errorf("selfupdate: state snapshot: %w", err)
	}
	return s.Update(ctx, func(d *StateData) error {
		if from.Serial > d.Serial {
			d.Serial, d.Hash = from.Serial, from.Hash
		}
		if d.InstallID == "" {
			d.InstallID = from.InstallID
		}
		d.Handoff = nil
		return nil
	})
}

func defaultStatePath(j Journal) string {
	return strings.TrimSuffix(j.Path, ".json") + "-state.json"
}
