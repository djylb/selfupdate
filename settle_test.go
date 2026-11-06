package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sibling(t *testing.T, dir string, m *Manifest, current string, base *Updater) *Updater {
	t.Helper()
	u := memUpdater(t, dir, m, current)
	u.Trust, u.Sources = base.Trust, base.Sources
	return u
}

func actionRel(version string) Release {
	r := dataRel(version)
	r.Artifacts[0].Action = &Action{Kind: "inst"}
	return r
}

// twoMembers offers one release as a plain file to "app" and through an
// installer to "tool".
func twoMembers() *Manifest {
	r := dataRel("2.0.0")
	a := artifactFor("tool", "2.0.0", FormatRaw, []byte("2.0.0"))
	a.Action = &Action{Kind: "inst"}
	r.Artifacts = append(r.Artifacts, a)
	return manifestOf("app", r)
}

func TestSuccessfulReinstallIsNoFailure(t *testing.T) {
	dir := t.TempDir()
	u := memUpdater(t, dir, manifestOf("app", dataRel("1.0.0")), "1.0.0")
	u.Grants = []string{GrantReinstall}
	p, err := u.Check(bg)
	must(t, err)
	must(t, u.Apply(bg, p.Candidate))
	must(t, u.Journal.Commit(bg))
	_, err = u.Check(bg)
	must(t, err)
	d, _ := u.State.Load(bg)
	if len(d.Failed) != 0 || d.Attempt != nil {
		t.Errorf("failed=%+v attempt=%+v", d.Failed, d.Attempt)
	}
}

func TestRollbackSurvivesCheckBeforeRestart(t *testing.T) {
	dir := t.TempDir()
	m := manifestOf("app", dataRel("2.0.0"))
	old := memUpdater(t, dir, m, "1.0.0")
	p, err := old.Check(bg)
	must(t, err)
	must(t, old.Apply(bg, p.Candidate))
	running := sibling(t, dir, m, "2.0.0", old)
	must(t, running.Journal.Rollback(bg))
	_, err = running.Check(bg)
	must(t, err)
	p, err = old.Check(bg)
	must(t, err)
	if d, _ := old.State.Load(bg); len(d.Failed) != 1 || p.Candidate != nil {
		t.Errorf("failed=%+v candidate=%v", d.Failed, p.Candidate)
	}
}

func TestSecondInstallerNeitherWaitsNorRepeats(t *testing.T) {
	dir := t.TempDir()
	m := manifestOf("app", actionRel("2.0.0"))
	first := memUpdater(t, dir, m, "1.0.0")
	second := sibling(t, dir, m, "1.0.0", first)
	dl := filepath.Join(dir, "dl")
	must(t, os.Mkdir(dl, 0o755))
	first.DownloadDir, second.DownloadDir = dl, dl
	entered, release := make(chan struct{}), make(chan struct{})
	first.Actions = map[string]ActionFunc{"inst": func(context.Context, ActionContext) (ActionResult, error) {
		close(entered)
		<-release
		return ActionDone, nil
	}}
	second.Actions = map[string]ActionFunc{"inst": func(context.Context, ActionContext) (ActionResult, error) {
		t.Error("the installer ran twice")
		return ActionDone, nil
	}}
	p1, err := first.Check(bg)
	must(t, err)
	p2, err := second.Check(bg)
	must(t, err)
	done := make(chan error, 1)
	go func() { done <- first.Apply(bg, p1.Candidate) }()
	<-entered
	if err := second.Apply(bg, p2.Candidate); !errors.Is(err, ErrBusy) {
		t.Errorf("during the action: %v", err)
	}
	close(release)
	must(t, <-done)
	if err := second.Apply(bg, p2.Candidate); !errors.Is(err, ErrPendingRestart) {
		t.Errorf("after the action: %v", err)
	}
	if _, err := second.Check(bg); !errors.Is(err, ErrPendingRestart) {
		t.Errorf("check after the action: %v", err)
	}
	// The new version takes over and the record ends without a failure.
	next := sibling(t, dir, m, "2.0.0", first)
	_, err = next.Check(bg)
	must(t, err)
	if d, _ := next.State.Load(bg); d.Attempt != nil || len(d.Failed) != 0 {
		t.Errorf("attempt=%+v failed=%+v", d.Attempt, d.Failed)
	}
}

func TestFinishedActionWithoutTakeoverFailsAfterTimeout(t *testing.T) {
	dir := t.TempDir()
	u := memUpdater(t, dir, manifestOf("app", actionRel("2.0.0")), "1.0.0")
	u.Actions = map[string]ActionFunc{"inst": func(context.Context, ActionContext) (ActionResult, error) {
		return ActionDone, nil
	}}
	p, err := u.Check(bg)
	must(t, err)
	must(t, u.Apply(bg, p.Candidate))
	now := testNow.Add(2 * u.backoff(1))
	u.Now = func() time.Time { return now }
	_, err = u.Check(bg)
	must(t, err)
	if d, _ := u.State.Load(bg); d.Attempt != nil || len(d.Failed) != 1 {
		t.Errorf("attempt=%+v failed=%+v", d.Attempt, d.Failed)
	}
}

func TestActionRefusedWhileSwapPending(t *testing.T) {
	dir := t.TempDir()
	m := twoMembers()
	tool := memUpdater(t, dir, m, "1.0.0")
	tool.Name = "tool"
	app := sibling(t, dir, m, "1.0.0", tool)
	tool.Actions = map[string]ActionFunc{"inst": func(context.Context, ActionContext) (ActionResult, error) {
		t.Error("the action ran over a pending swap")
		return ActionDone, nil
	}}
	pa, err := app.Check(bg)
	must(t, err)
	tool.Verify = func(ctx context.Context, _ *Candidate, _ []string, _ io.ReaderAt) error {
		return app.Apply(ctx, pa.Candidate)
	}
	pt, err := tool.Check(bg)
	must(t, err)
	if err := tool.Apply(bg, pt.Candidate); !errors.Is(err, ErrBusy) {
		t.Errorf("got %v", err)
	}
}

func TestSwapRefusedDuringHandoff(t *testing.T) {
	dir := t.TempDir()
	m := twoMembers()
	tool := memUpdater(t, dir, m, "1.0.0")
	tool.Name = "tool"
	app := sibling(t, dir, m, "1.0.0", tool)
	tool.Actions = map[string]ActionFunc{"inst": func(context.Context, ActionContext) (ActionResult, error) {
		return ActionHandedOff, nil
	}}
	pa, err := app.Check(bg)
	must(t, err)
	pt, err := tool.Check(bg)
	must(t, err)
	must(t, tool.Apply(bg, pt.Candidate))
	if err := app.Apply(bg, pa.Candidate); !errors.Is(err, ErrBusy) {
		t.Errorf("got %v", err)
	}
	if err := app.Install(bg, pa.Candidate); !errors.Is(err, ErrBusy) {
		t.Errorf("install: %v", err)
	}
}

func TestSnapshotKeepsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	u := memUpdater(t, dir, manifestOf("app", actionRel("2.0.0")), "1.0.0")
	must(t, os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"future":1}`), 0o600))
	var snap []byte
	u.Actions = map[string]ActionFunc{"inst": func(_ context.Context, a ActionContext) (ActionResult, error) {
		snap = a.StateSnapshot
		return ActionDone, nil
	}}
	p, err := u.Check(bg)
	must(t, err)
	must(t, u.Apply(bg, p.Candidate))
	var all map[string]json.RawMessage
	must(t, json.Unmarshal(snap, &all))
	if _, ok := all["future"]; !ok {
		t.Errorf("snapshot %s", snap)
	}
}

func TestNoOfferOfUnusableDowngrade(t *testing.T) {
	low := dataRel("1.0.0")
	low.Artifacts[0].OS = "windows"
	m := manifestOf("app", low, dataRel("2.0.0"))
	m.Rules = []Rule{{ID: "a", Effect: EffectAllow, From: "=2.0.0", To: "=1.0.0"}}
	r, err := Resolve(m, queryAt("2.0.0"))
	must(t, err)
	if len(r.Offers) != 0 {
		t.Errorf("offers %+v", r.Offers)
	}
}

type readOnlyState struct{ State }

func (readOnlyState) Update(context.Context, func(*StateData) error) error {
	return errors.New("read-only")
}

func TestCheckWithoutWriteAccess(t *testing.T) {
	dir := t.TempDir()
	u := memUpdater(t, dir, manifestOf("app", dataRel("2.0.0")), "1.0.0")
	a := artifactFor("app", "2.0.0", FormatRaw, []byte("2.0.0"))
	must(t, u.State.Update(bg, func(d *StateData) error {
		d.Attempt = &Handoff{At: testNow, From: "1.0.0", To: "2.0.0", Digest: a.Digest()}
		return nil
	}))
	u.State = readOnlyState{u.State}
	p, err := u.Check(bg)
	must(t, err)
	if len(p.Warnings) == 0 || p.Candidate != nil {
		t.Errorf("warnings=%v candidate=%v", p.Warnings, p.Candidate)
	}
}
