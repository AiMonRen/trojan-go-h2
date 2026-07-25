package trafficoutbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileRoundTripAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	file, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	want := State{
		PendingSyncID: "sync-1",
		Pending:       map[string]Traffic{"hash-a": {Up: 10, Down: 20}},
		Queued:        map[string]Traffic{"hash-b": {Up: 30, Down: 40}},
	}
	if err := file.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	got, err := file.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.PendingSyncID != "sync-1" || got.Pending["hash-a"] != (Traffic{Up: 10, Down: 20}) || got.Queued["hash-b"] != (Traffic{Up: 30, Down: 40}) {
		t.Fatalf("unexpected state: %+v", got)
	}
	if err := file.Save(State{}); err != nil {
		t.Fatalf("remove empty state: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty state must remove file, stat err=%v", err)
	}
}

func TestFileRejectsCorruptOrInconsistentState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	file, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	if _, err := file.Load(); err == nil {
		t.Fatal("corrupt outbox must fail closed")
	}
	if err := file.Save(State{Pending: map[string]Traffic{"hash": {Up: 1}}}); err == nil {
		t.Fatal("pending traffic without sync id must be rejected")
	}
	if err := file.Save(State{PendingSyncID: "orphan"}); err == nil {
		t.Fatal("sync id without pending traffic must be rejected")
	}
}

func TestCopyStateIsIndependent(t *testing.T) {
	original := State{PendingSyncID: "sync", Pending: map[string]Traffic{"hash": {Up: 1}}, Queued: map[string]Traffic{"hash": {Down: 2}}}
	copy := CopyState(original)
	copy.Pending["hash"] = Traffic{Up: 9}
	copy.Queued["hash"] = Traffic{Down: 8}
	if original.Pending["hash"].Up != 1 || original.Queued["hash"].Down != 2 {
		t.Fatalf("copy mutated original: %+v", original)
	}
}
