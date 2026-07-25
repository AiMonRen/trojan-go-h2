package trafficoutbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const currentVersion = 1

// Traffic is expressed from the client's perspective: Up is client upload and
// Down is client download.
type Traffic struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// State contains one immutable in-flight batch and traffic accumulated after
// that batch was frozen. PendingSyncID must stay stable until Pending is
// acknowledged by the receiver.
type State struct {
	Version       int                `json:"version"`
	PendingSyncID string             `json:"pending_sync_id,omitempty"`
	Pending       map[string]Traffic `json:"pending,omitempty"`
	Queued        map[string]Traffic `json:"queued,omitempty"`
}

// File persists outbox state using a same-directory temporary file followed by
// an atomic rename. The file and parent directory are synced before Save
// returns so a successful checkpoint survives a process or machine restart.
type File struct {
	path string
}

func NewFile(path string) (*File, error) {
	if path == "" {
		return nil, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve traffic outbox path: %w", err)
	}
	return &File{path: absolute}, nil
}

func (f *File) Path() string {
	if f == nil {
		return ""
	}
	return f.path
}

func Empty(state State) bool {
	return state.PendingSyncID == "" && len(state.Pending) == 0 && len(state.Queued) == 0
}

func CloneTraffic(source map[string]Traffic) map[string]Traffic {
	if len(source) == 0 {
		return make(map[string]Traffic)
	}
	clone := make(map[string]Traffic, len(source))
	for hash, value := range source {
		clone[hash] = value
	}
	return clone
}

func Normalize(state State) State {
	state.Version = currentVersion
	if state.Pending == nil {
		state.Pending = make(map[string]Traffic)
	}
	if state.Queued == nil {
		state.Queued = make(map[string]Traffic)
	}
	return state
}

func Validate(state State) error {
	if state.Version != 0 && state.Version != currentVersion {
		return fmt.Errorf("unsupported traffic outbox version %d", state.Version)
	}
	if len(state.Pending) > 0 && state.PendingSyncID == "" {
		return errors.New("pending traffic is missing a sync id")
	}
	if len(state.Pending) == 0 && state.PendingSyncID != "" {
		return errors.New("pending sync id has no traffic")
	}
	for group, traffic := range map[string]map[string]Traffic{"pending": state.Pending, "queued": state.Queued} {
		for hash, value := range traffic {
			if hash == "" {
				return fmt.Errorf("%s traffic contains an empty user hash", group)
			}
			if value.Up == 0 && value.Down == 0 {
				return fmt.Errorf("%s traffic contains an empty value for user %s", group, hash)
			}
		}
	}
	return nil
}

func (f *File) Load() (State, error) {
	state := Normalize(State{})
	if f == nil {
		return state, nil
	}
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read traffic outbox %s: %w", f.path, err)
	}
	if len(data) == 0 {
		return State{}, fmt.Errorf("traffic outbox %s is empty", f.path)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("decode traffic outbox %s: %w", f.path, err)
	}
	if err := Validate(state); err != nil {
		return State{}, fmt.Errorf("validate traffic outbox %s: %w", f.path, err)
	}
	return Normalize(state), nil
}

func (f *File) Save(state State) error {
	if f == nil {
		return nil
	}
	state = Normalize(state)
	if err := Validate(state); err != nil {
		return fmt.Errorf("validate traffic outbox state: %w", err)
	}
	if Empty(state) {
		return f.Remove()
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode traffic outbox: %w", err)
	}
	data = append(data, '\n')

	directory := filepath.Dir(f.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create traffic outbox directory %s: %w", directory, err)
	}
	temporary, err := os.CreateTemp(directory, ".traffic-outbox-*")
	if err != nil {
		return fmt.Errorf("create traffic outbox temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure traffic outbox temporary file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write traffic outbox temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync traffic outbox temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close traffic outbox temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, f.path); err != nil {
		return fmt.Errorf("replace traffic outbox %s: %w", f.path, err)
	}
	committed = true
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync traffic outbox directory %s: %w", directory, err)
	}
	return nil
}

func (f *File) Remove() error {
	if f == nil {
		return nil
	}
	err := os.Remove(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove traffic outbox %s: %w", f.path, err)
	}
	if err := syncDirectory(filepath.Dir(f.path)); err != nil {
		return fmt.Errorf("sync traffic outbox directory after remove: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// CopyState returns a deep copy suitable for mutation before an atomic Save.
func CopyState(state State) State {
	return State{
		Version:       currentVersion,
		PendingSyncID: state.PendingSyncID,
		Pending:       CloneTraffic(state.Pending),
		Queued:        CloneTraffic(state.Queued),
	}
}
