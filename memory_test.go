package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"
)

// memSource serves one manifest. Its map makes the type uncomparable, which a
// Source may be.
type memSource struct {
	data map[string][]byte
	doc  []byte
}

func (s memSource) Fetch(context.Context) ([]byte, error) { return s.doc, nil }

func (s memSource) Open(_ context.Context, a Artifact, off int64) (io.ReadCloser, int64, error) {
	d, ok := s.data[a.URL]
	if !ok {
		return nil, 0, errors.New("no artifact")
	}
	return io.NopCloser(bytes.NewReader(d[off:])), off, nil
}

func dataRel(version string) Release {
	return Release{Version: version, Artifacts: []Artifact{artifactFor("app", version, FormatRaw, []byte(version))}}
}

func memData(m *Manifest) map[string][]byte {
	out := map[string][]byte{}
	for i := range m.Releases {
		out[m.Releases[i].Version] = []byte(m.Releases[i].Version)
	}
	return out
}

// memUpdater returns an updater of m running current, with a state in dir.
func memUpdater(t *testing.T, dir string, m *Manifest, current string) *Updater {
	t.Helper()
	k := newTestKey(t)
	return &Updater{
		Sources: []Source{memSource{doc: mustSign(t, m, k), data: memData(m)}},
		State:   FileState(filepath.Join(dir, "state.json")),
		Trust:   k.trust(), Product: "app", Name: "app", Current: current, OS: "linux", Arch: "amd64",
		Now: func() time.Time { return testNow }, Executable: filepath.Join(dir, "app"),
		Journal: Journal{Path: filepath.Join(dir, "journal.json")},
		Files:   []File{{Target: filepath.Join(dir, "target")}},
	}
}

func queryAt(current string, grants ...string) Query {
	return Query{Current: current, Name: "app", OS: "linux", Arch: "amd64", Grants: grants}
}

func TestActionIsExclusiveAndRecordedFirst(t *testing.T) {
	dir := t.TempDir()
	r := dataRel("2.0.0")
	r.Artifacts[0].Action = &Action{Kind: "inst"}
	m := manifestOf("app", r)
	u1, u2 := memUpdater(t, dir, m, "1.0.0"), memUpdater(t, dir, m, "1.0.0")
	u2.Trust, u2.Sources = u1.Trust, u1.Sources
	var second error
	u2.Actions = map[string]ActionFunc{"inst": func(context.Context, ActionContext) (ActionResult, error) {
		t.Error("second installer started")
		return ActionDone, nil
	}}
	p2, err := u2.Check(bg)
	must(t, err)
	u1.Actions = map[string]ActionFunc{"inst": func(ctx context.Context, _ ActionContext) (ActionResult, error) {
		d, err := u1.State.Load(ctx)
		must(t, err)
		if d.Handoff == nil {
			t.Error("no handoff recorded before the action ran")
		}
		second = u2.Apply(ctx, p2.Candidate)
		return ActionDone, errors.New("installer failed")
	}}
	p1, err := u1.Check(bg)
	must(t, err)
	if err := u1.Apply(bg, p1.Candidate); err == nil {
		t.Error("the action's error was lost")
	}
	if !errors.Is(second, ErrBusy) {
		t.Errorf("second Apply: %v", second)
	}
	d, err := u1.State.Load(bg)
	must(t, err)
	if d.Handoff != nil || len(d.Failed) != 0 {
		t.Errorf("after an action error: %+v", d)
	}
}

func TestForceOnLatestReinstalls(t *testing.T) {
	m := manifestOf("app", dataRel("1.0.0"), dataRel("2.0.0"))
	r, err := Resolve(m, queryAt("2.0.0", GrantReinstall, GrantDowngradeAny))
	must(t, err)
	if r.Next == nil || r.Next.Version != "2.0.0" || !r.Reinstall || r.Downgrade {
		t.Errorf("%+v", r)
	}
	r, err = Resolve(m, queryAt("2.0.0", GrantDowngradeAny))
	must(t, err)
	if r.Next == nil || r.Next.Version != "1.0.0" || !r.Downgrade {
		t.Errorf("downgrade alone: %+v", r)
	}
}

func TestUncomparableSourceFallsBack(t *testing.T) {
	dir := t.TempDir()
	m := manifestOf("app", dataRel("2.0.0"))
	u := memUpdater(t, dir, m, "1.0.0")
	good := u.Sources[0].(memSource)
	empty := good
	empty.data = nil
	u.Sources = []Source{empty, good}
	p, err := u.Check(bg)
	must(t, err)
	must(t, u.Apply(bg, p.Candidate))
}

func TestHandoffTimeoutClosesEdgeAtOnce(t *testing.T) {
	dir := t.TempDir()
	m := manifestOf("app", dataRel("2.0.0"))
	u := memUpdater(t, dir, m, "1.0.0")
	must(t, u.State.Update(bg, func(d *StateData) error {
		d.Handoff = &Handoff{At: testNow.Add(-2 * time.Hour), From: "1.0.0", To: "2.0.0", Digest: m.Releases[0].Artifacts[0].Digest()}
		return nil
	}))
	p, err := u.Check(bg)
	must(t, err)
	if p.Candidate != nil {
		t.Error("the edge that just failed is offered")
	}
}

func TestFailureSurvivesCheckOfOtherVersion(t *testing.T) {
	dir := t.TempDir()
	m := manifestOf("app", dataRel("2.0.0"), dataRel("3.0.0"))
	old := memUpdater(t, dir, m, "1.0.0")
	must(t, old.RecordOutcome(bg, Outcome{Status: StatusRolledBack, Cause: RollbackUnconfirmed, Previous: "1.0.0", Version: "3.0.0", Digest: m.Releases[1].Artifacts[0].Digest()}))
	other := *old
	other.Current = "2.0.0"
	_, err := other.Check(bg)
	must(t, err)
	p, err := old.Check(bg)
	must(t, err)
	if p.Route.Next == nil || p.Route.Next.Version != "2.0.0" {
		t.Errorf("failure forgotten: %+v", p.Route.Next)
	}
}

func TestStaleFailureOfGoneDigestIsPruned(t *testing.T) {
	dir := t.TempDir()
	u := memUpdater(t, dir, manifestOf("app", dataRel("2.0.0")), "1.0.0")
	must(t, u.State.Update(bg, func(d *StateData) error {
		d.Failed = []FailedEdge{{From: "1.0.0", To: "2.0.0", Digest: "gone", Rejected: true}}
		return nil
	}))
	_, err := u.Check(bg)
	must(t, err)
	d, err := u.State.Load(bg)
	must(t, err)
	if len(d.Failed) != 0 {
		t.Errorf("%+v", d.Failed)
	}
}

// A rollback whose Outcome never reached RecordOutcome is still noticed.
func TestRollbackWithoutOutcomeIsRemembered(t *testing.T) {
	dir := t.TempDir()
	m := manifestOf("app", dataRel("2.0.0"))
	u := memUpdater(t, dir, m, "1.0.0")
	p, err := u.Check(bg)
	must(t, err)
	must(t, u.Apply(bg, p.Candidate))
	j, err := u.journal()
	must(t, err)
	must(t, j.Rollback(bg))
	p, err = u.Check(bg)
	must(t, err)
	if p.Candidate != nil {
		t.Error("retried at once after a rollback")
	}
}

func TestInterruptedRollbackIsNotRemembered(t *testing.T) {
	dir := t.TempDir()
	m := manifestOf("app", dataRel("2.0.0"))
	u := memUpdater(t, dir, m, "1.0.0")
	p, err := u.Check(bg)
	must(t, err)
	must(t, u.Apply(bg, p.Candidate))
	j, err := u.journal()
	must(t, err)
	must(t, j.Rollback(bg))
	must(t, u.RecordOutcome(bg, Outcome{Status: StatusRolledBack, Cause: RollbackInterrupted, Previous: "1.0.0", Version: "2.0.0"}))
	p, err = u.Check(bg)
	must(t, err)
	if p.Candidate == nil {
		t.Error("an interruption closed the edge")
	}
}

func TestDowngradedRecordNeedsAnOfferedDowngrade(t *testing.T) {
	dir := t.TempDir()
	m := manifestOf("app", dataRel("1.4.0"), dataRel("1.5.0"))
	m.Rules = []Rule{{ID: "cancel", Effect: EffectAllow, From: "<2.0.0-0", To: ">=2.0.0-0"}}
	u := memUpdater(t, dir, m, "1.4.0")
	must(t, u.State.Update(bg, func(d *StateData) error { d.Downgraded = []string{"1.5.0"}; return nil }))
	p, err := u.Check(bg)
	must(t, err)
	if p.Route.Next == nil || p.Route.Next.Version != "1.5.0" {
		t.Errorf("%+v", p.Route)
	}
}

func TestRejectedEdgeBindsOnlyItsSource(t *testing.T) {
	dir := t.TempDir()
	r2 := dataRel("2.0.0")
	r2.Provides = LibraryCapabilities()
	m := manifestOf("app", r2, dataRel("3.0.0"))
	u := memUpdater(t, dir, m, "1.0.0")
	must(t, u.State.Update(bg, func(d *StateData) error {
		recordRejected(d, "1.0.0", "3.0.0", m.Releases[1].Artifacts[0].Digest())
		return nil
	}))
	p, err := u.Check(bg)
	must(t, err)
	if p.Route.Goal != "3.0.0" {
		t.Errorf("goal %s", p.Route.Goal)
	}
}

func TestUnreachableTargetIsHeld(t *testing.T) {
	m := manifestOf("app", dataRel("1.0.0"), dataRel("2.0.0"))
	for _, target := range []string{"1.0.0", "9.0.0"} {
		q := queryAt("2.0.0")
		q.Target = target
		r, err := Resolve(m, q)
		must(t, err)
		if r.Status != RouteHeld || len(r.Blocked) == 0 {
			t.Errorf("target %s: status %v, blocked %v", target, r.Status, r.Blocked)
		}
	}
}

func TestNoticeOnEdgeFacts(t *testing.T) {
	r2 := dataRel("2.0.0")
	r2.Labels = []string{"sec"}
	m := manifestOf("app", r2)
	m.Rules = []Rule{
		{ID: "n1", Effect: EffectNotice, To: ">=2.0.0-0", When: []Condition{{Fact: "edge.crosses", In: []string{"major"}}}},
		{ID: "n2", Effect: EffectNotice, To: ">=2.0.0-0", When: []Condition{{Fact: "to.label", In: []string{"sec"}}}},
		{ID: "n3", Effect: EffectNotice, To: ">=2.0.0-0", When: []Condition{{Fact: "to.label", In: []string{"other"}}}},
	}
	r, err := Resolve(m, queryAt("1.0.0"))
	must(t, err)
	if len(r.Notices) != 2 {
		t.Errorf("%+v", r.Notices)
	}
}

func TestBackoffCallbackHoldsNoStateLock(t *testing.T) {
	dir := t.TempDir()
	u := memUpdater(t, dir, manifestOf("app", dataRel("2.0.0")), "1.0.0")
	digest := "d"
	u.FailureBackoff = func(int) time.Duration {
		ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
		defer cancel()
		if err := u.State.Update(ctx, func(*StateData) error { return nil }); err != nil {
			t.Errorf("state locked in the callback: %v", err)
		}
		return time.Hour
	}
	must(t, u.RecordOutcome(bg, Outcome{Status: StatusRolledBack, Cause: RollbackUnconfirmed, Previous: "1.0.0", Version: "2.0.0", Digest: digest}))
	_, err := u.Check(bg)
	must(t, err)
}

func TestCandidateArtifactIsACopy(t *testing.T) {
	dir := t.TempDir()
	r := dataRel("2.0.0")
	r.Artifacts[0].Action = &Action{Kind: "inst", Params: []byte(`{"a":1}`)}
	u := memUpdater(t, dir, manifestOf("app", r), "1.0.0")
	u.Actions = map[string]ActionFunc{"inst": func(context.Context, ActionContext) (ActionResult, error) { return ActionDone, nil }}
	p, err := u.Check(bg)
	must(t, err)
	c := p.Candidate
	c.Artifact.Action.Kind = "changed"
	c.Artifact.Action.Params[0] = 'x'
	if c.artifact.Action.Kind != "inst" || c.artifact.Action.Params[0] != '{' {
		t.Errorf("%+v", c.artifact.Action)
	}
}

func TestSimulateEnumeratesRulePlatforms(t *testing.T) {
	m := manifestOf("app", dataRel("2.0.0"))
	m.Rules = []Rule{{ID: "bsd", Effect: EffectBlock, To: "*", When: []Condition{{Fact: "os", In: []string{"freebsd"}}}}}
	rows, _ := m.Simulate(SimOptions{})
	for _, r := range rows {
		if r.OS == "freebsd" {
			return
		}
	}
	t.Error("the os named by a rule was not tried")
}
