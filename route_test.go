package selfupdate

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const zero64 = "0000000000000000000000000000000000000000000000000000000000000000"

// rel makes a release with one raw artifact for every platform.
func rel(version string, provides ...string) Release {
	r := Release{Version: version, Artifacts: []Artifact{artifactFor("app", "a-"+version, FormatRaw, []byte(version))}}
	if len(provides) > 0 {
		r.Provides = append(LibraryCapabilities(), provides...)
	}
	return r
}

func relNeeds(version string, needs []string, provides ...string) Release {
	r := rel(version, provides...)
	r.Requires = needs
	return r
}

func resolve(t *testing.T, m *Manifest, q Query) *Route {
	t.Helper()
	if q.Name == "" {
		q.Name = "app"
	}
	rt, err := Resolve(m, q)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func nextOf(rt *Route) string {
	if rt.Next == nil {
		return ""
	}
	return rt.Next.Version
}

// TestResolvePlainSelection compares with the rule the package had before
// paths existed: with no rules, the highest visible release with an artifact.
func TestResolvePlainSelection(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for range 300 {
		var releases []Release
		for i := range rng.IntN(6) {
			r := rel(fmt.Sprintf("1.%d.0", i))
			switch rng.IntN(3) {
			case 0:
				r.Channels = []string{"beta"}
			case 1:
				r.Artifacts[0].OS = "plan9"
			}
			releases = append(releases, r)
		}
		rng.Shuffle(len(releases), func(i, j int) { releases[i], releases[j] = releases[j], releases[i] })
		current, want := fmt.Sprintf("1.%d.5", rng.IntN(4)), ""
		for _, r := range releases {
			c, _ := CompareVersions(r.Version, current)
			w, _ := CompareVersions(r.Version, cmp.Or(want, current))
			if c > 0 && w > 0 && len(r.Channels) == 0 && r.Artifacts[0].OS == "" {
				want = r.Version
			}
		}
		if got := nextOf(resolve(t, manifestOf("app", releases...), Query{Current: current, OS: "linux"})); got != want {
			t.Fatalf("from %s: %q, want %q: %+v", current, got, want, releases)
		}
	}
}

// TestResolveCapabilityBackport is scenario 1 of the review: a capability
// backported to a maintenance line must not count for the newer line, which
// lacks it. With cumulative capabilities the client walked into 2.5 for good.
func TestResolveCapabilityBackport(t *testing.T) {
	m := manifestOf("app", rel("1.99.1", "X"), rel("2.5.0", "other"), relNeeds("3.0.0", []string{"X"}, "X"))
	rt := resolve(t, m, Query{Current: "1.5.0"})
	if nextOf(rt) != "1.99.1" || rt.Goal != "3.0.0" {
		t.Fatalf("route %+v", rt)
	}
}

func unstableGate() *Manifest {
	m := manifestOf("app", rel("1.7.0", "P"), rel("1.8.0", "P"), rel("1.9.0", "P"), relNeeds("2.0.0", []string{"P"}, "P"))
	m.Facts = map[string]Fact{"peer.client": {Type: "version"}}
	m.Rules = []Rule{{
		ID: "peer", Effect: EffectBlock, From: ">=1.9.0", To: ">=2.0.0-0", Unlock: []string{GrantForce},
		When: []Condition{{Fact: "peer.client", Range: "<1.99.0-0", Missing: "match"}},
	}}
	return m
}

// TestResolvePrefersCertain is scenario 2: the outcome must not depend on a
// transient failure. Among hops that may reach the same height the one that
// reaches it for certain wins, with or without a failure on the highest hop.
func TestResolvePrefersCertain(t *testing.T) {
	m := unstableGate()
	q := Query{Current: "1.5.0", Facts: map[string][]string{"peer.client": {"1.0.0"}}}
	rt := resolve(t, m, q)
	if nextOf(rt) != "1.8.0" || rt.Goal != "2.0.0" {
		t.Fatalf("route %+v", rt)
	}
	q.LocalRules = []Rule{{ID: "failed", Effect: EffectBlock, To: "=1.9.0"}}
	if rt := resolve(t, m, q); nextOf(rt) != "1.8.0" {
		t.Fatalf("after failure %+v", rt)
	}
	// Standing in front of the gate it holds; the reason is there.
	q.LocalRules, q.Current, q.Capabilities = nil, "1.9.0", []string{"P"}
	rt = resolve(t, m, q)
	if rt.Next != nil || rt.Status != RouteHeld || len(rt.Offers) != 1 || rt.Offers[0].Needs[0] != GrantForce {
		t.Fatalf("at the gate %+v", rt)
	}
}

// TestResolveRemainingRisk pins the documented cost of optimism: a real fork
// where the higher way is only predicted is still taken.
func TestResolveRemainingRisk(t *testing.T) {
	m := manifestOf("app", rel("2.5.0"), rel("2.6.0"), rel("3.0.0"))
	m.Facts = map[string]Fact{"gate": {}}
	m.Rules = []Rule{
		{ID: "a", Effect: EffectBlock, From: ">=2.6.0", To: ">=3.0.0-0", When: []Condition{{Fact: "gate", In: []string{"shut"}, Missing: "match"}}},
		{ID: "b", Effect: EffectBlock, From: "=2.5.0", To: ">=2.6.0-0", URL: "u"},
		{ID: "c", Effect: EffectBlock, From: "<2.5.0-0", To: ">=3.0.0-0", URL: "u"},
	}
	rt := resolve(t, m, Query{Current: "1.0.0", Facts: map[string][]string{"gate": {"shut"}}})
	if nextOf(rt) != "2.6.0" || rt.Goal != "2.6.0" || rt.Horizon != "3.0.0" {
		t.Fatalf("route %+v", rt)
	}
}

// TestResolveAllowOnFutureEdge: an allow that cancels a baseline gate has to
// count for future edges too, or the route misses the stepping stone.
func TestResolveAllowOnFutureEdge(t *testing.T) {
	m := manifestOf("app", rel("1.99.0", "x"), rel("1.100.0", "x"), rel("2.0.0", "x"))
	m.Baseline = []Rule{{ID: "major", Effect: EffectBlock, When: []Condition{{Fact: "edge.crosses", In: []string{"major"}}}}}
	m.Rules = []Rule{{ID: "bridge", Effect: EffectAllow, From: "=1.99.0", To: "=2.0.0"}}
	rt := resolve(t, m, Query{Current: "1.5.0"})
	if nextOf(rt) != "1.99.0" || rt.Goal != "2.0.0" {
		t.Fatalf("route %+v", rt)
	}
}

// TestResolveExportGate is scenario 4: the gate of a migration, with the upper
// bound the design asks for, leaves later versions alone.
func TestResolveExportGate(t *testing.T) {
	m := manifestOf("app", rel("1.99.0"), rel("2.0.0"), rel("2.1.0"), rel("2.2.0"))
	m.Facts = map[string]Fact{"export_state": {}}
	gate := Rule{ID: "export", Effect: EffectBlock, To: ">=2.0.0-0", URL: "u",
		When: []Condition{{Fact: "export_state", In: []string{"done"}, Negate: true, Missing: "match"}}}
	m.Rules = []Rule{gate}
	if rep := m.Lint(LintOptions{}); !slices.ContainsFunc(rep.Findings, func(f Finding) bool { return f.Code == "gate-reopens" }) {
		t.Errorf("no warning for a gate that reopens: %+v", rep.Findings)
	}
	if rt := resolve(t, m, Query{Current: "2.1.0"}); rt.Next != nil {
		t.Errorf("without the bound the gate reopens, as linted: %+v", rt)
	}
	gate.From = "<2.0.0-0"
	m.Rules = []Rule{gate}
	if rt := resolve(t, m, Query{Current: "1.5.0"}); nextOf(rt) != "1.99.0" {
		t.Errorf("old version: %+v", rt)
	}
	q := Query{Current: "1.99.0", Facts: map[string][]string{"export_state": {"done"}}}
	if rt := resolve(t, m, q); nextOf(rt) != "2.2.0" {
		t.Errorf("after export: %+v", rt)
	}
	if rt := resolve(t, m, Query{Current: "2.1.0"}); nextOf(rt) != "2.2.0" {
		t.Errorf("past the bridge: %+v", rt)
	}
}

// TestResolveGoalHorizon: a background check must not read "reachable" for a
// step it will never take, and Blocked has to say what stops it.
func TestResolveGoalHorizon(t *testing.T) {
	m := manifestOf("app", rel("1.9.0"), rel("2.0.0"))
	m.Baseline = []Rule{{ID: "major", Effect: EffectBlock, Unlock: []string{"accept:major"}, When: []Condition{{Fact: "edge.crosses", In: []string{"major"}}}}}
	rt := resolve(t, m, Query{Current: "1.5.0"})
	if rt.Goal != "1.9.0" || rt.Horizon != "2.0.0" || rt.Latest != "2.0.0" || len(rt.Blocked) != 1 || rt.Blocked[0].RuleID != "major" {
		t.Fatalf("route %+v", rt)
	}
	if rt := resolve(t, m, Query{Current: "1.9.0", Grants: []string{"accept:major"}}); nextOf(rt) != "2.0.0" || rt.Forced[0] != "major" {
		t.Fatalf("accepted %+v", rt)
	}
}

// TestResolveImplicitCapabilities: a release that only a format the client
// lacks can reach is bridged by a version providing it, with no rule at all.
func TestResolveImplicitCapabilities(t *testing.T) {
	zst := rel("2.0.0")
	zst.Artifacts[0].rawFormat, zst.Artifacts[0].Format = "tar.zst", FormatUnknown
	m := manifestOf("app", rel("1.99.0", "format:tar.zst"), rel("1.100.0", "plain"), zst)
	rt := resolve(t, m, Query{Current: "1.5.0"})
	if nextOf(rt) != "1.99.0" || rt.Goal != "2.0.0" {
		t.Fatalf("route %+v", rt)
	}
	if rt := resolve(t, m, Query{Current: "1.100.0"}); rt.Next != nil || len(rt.Unusable) != 1 {
		t.Fatalf("no bridge from here: %+v", rt)
	}
	// Unknown capabilities are a prediction, not a certainty.
	m = manifestOf("app", rel("1.99.0"), zst)
	if rt := resolve(t, m, Query{Current: "1.5.0"}); rt.Goal != "1.99.0" || rt.Horizon != "2.0.0" {
		t.Fatalf("unknown caps %+v", rt)
	}
}

func TestResolveLocalRules(t *testing.T) {
	m := manifestOf("app", rel("2.0.0"))
	for name, r := range map[string]Rule{
		"allow":   {ID: "x", Effect: EffectAllow},
		"unknown": {ID: "x", Effect: "promote"},
		"range":   {ID: "x", Effect: EffectBlock, From: "bad"},
	} {
		if _, err := Resolve(m, Query{Current: "1.0.0", Name: "app", LocalRules: []Rule{r}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The same id as a manifest rule is fine, and the kind tells them apart.
	m.Rules = []Rule{{ID: "x", Effect: EffectBlock, To: "=9.9.9"}}
	rt := resolve(t, m, Query{Current: "1.0.0", LocalRules: []Rule{{ID: "x", Effect: EffectBlock, To: "=2.0.0"}}})
	if rt.Next != nil || rt.Blocked[0].Kind != ReasonLocal {
		t.Fatalf("route %+v", rt)
	}
}

func TestResolveGates(t *testing.T) {
	back := manifestOf("app", rel("1.0.0"), rel("1.5.2"))
	back.Rules = []Rule{{ID: "back", Effect: EffectAllow, From: "=1.5.2", To: "=1.0.0"}}
	if rt := resolve(t, back, Query{Current: "1.5.2"}); rt.Next != nil || len(rt.Offers) != 1 {
		t.Errorf("no downgrade without a grant: %+v", rt)
	}
	if rt := resolve(t, back, Query{Current: "1.5.2", Grants: []string{GrantDowngradeOffer}}); nextOf(rt) != "1.0.0" || !rt.Downgrade {
		t.Errorf("offered downgrade: %+v", rt)
	}
	paused := rel("2.0.0")
	paused.Rollout = &Rollout{Percent: 100, Paused: true}
	m := manifestOf("app", paused)
	if rt := resolve(t, m, Query{Current: "1.0.0", Grants: []string{GrantForce, GrantRollout}, Target: "2.0.0"}); rt.Next != nil {
		t.Errorf("paused installed: %+v", rt)
	}
	half := rel("2.0.0")
	half.Rollout = &Rollout{Percent: 50}
	m = manifestOf("app", half)
	if rt := resolve(t, m, Query{Current: "1.0.0"}); rt.Next != nil {
		t.Errorf("no install id drew a place: %+v", rt)
	}
	if rt := resolve(t, m, Query{Current: "1.0.0", Grants: []string{GrantRollout}}); nextOf(rt) != "2.0.0" {
		t.Errorf("rollout grant: %+v", rt)
	}
	// Unknown rules hold by default and can be told to step aside.
	m = manifestOf("app", rel("2.0.0"))
	m.Rules = []Rule{{ID: "new", Effect: "shiny", To: ">=2.0.0-0", Unlock: []string{GrantForce}}}
	rt := resolve(t, m, Query{Current: "1.0.0"})
	if rt.Next != nil || !rt.Blocked[0].Unknown {
		t.Errorf("unknown rule: %+v", rt)
	}
	m.Rules[0].IfUnknown = "ignore"
	if rt := resolve(t, m, Query{Current: "1.0.0"}); nextOf(rt) != "2.0.0" {
		t.Errorf("ignored rule: %+v", rt)
	}
	// A notice informs and never routes, even one this client cannot read.
	m.Rules = []Rule{
		{ID: "n", Effect: EffectNotice, Class: "urgency", From: "<2.0.0", To: ">=2.0.0"},
		{ID: "future", Effect: EffectNotice, When: []Condition{{Fact: "os"}}},
	}
	rt = resolve(t, m, Query{Current: "1.0.0"})
	if nextOf(rt) != "2.0.0" || len(rt.Notices) != 1 || !rt.Notices[0].Reachable {
		t.Errorf("notice: %+v", rt)
	}
	// A target that needs a stone goes through it.
	m = manifestOf("app", rel("1.9.0", "x"), rel("2.0.0", "x"), rel("3.0.0", "x"))
	m.Rules = []Rule{{ID: "stone", Effect: EffectBlock, From: "<1.9.0", To: ">=2.0.0-0", URL: "u"}}
	rt = resolve(t, m, Query{Current: "1.0.0", Target: "2.0.0"})
	if nextOf(rt) != "1.9.0" || rt.Goal != "2.0.0" {
		t.Errorf("target: %+v", rt)
	}
	if rt := resolve(t, m, Query{Current: "1.0.0", Target: "7.0.0"}); rt.Next != nil {
		t.Errorf("no such target: %+v", rt)
	}
}

// TestResolveDeterministic checks that neither the order of the releases and
// rules nor repeating the call changes anything.
func TestResolveDeterministic(t *testing.T) {
	m := unstableGate()
	m.Rules = append(m.Rules,
		Rule{ID: "z", Effect: EffectBlock, To: "=1.7.0", Unlock: []string{"user"}},
		Rule{ID: "n", Effect: EffectNotice, From: "<3.0.0"},
		Rule{ID: "m", Effect: EffectNotice, From: "<3.0.0"})
	q := Query{Current: "1.5.0", Name: "app", Facts: map[string][]string{"peer.client": {"1.0.0"}}}
	want := resolve(t, m, q)
	rng := rand.New(rand.NewPCG(1, 2))
	for range 50 {
		s := *m
		s.Releases, s.Rules = slices.Clone(m.Releases), slices.Clone(m.Rules)
		rng.Shuffle(len(s.Releases), func(i, j int) { s.Releases[i], s.Releases[j] = s.Releases[j], s.Releases[i] })
		rng.Shuffle(len(s.Rules), func(i, j int) { s.Rules[i], s.Rules[j] = s.Rules[j], s.Rules[i] })
		if got := resolve(t, &s, q); !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v\nwant %+v", got, want)
		}
	}
}

func TestVersionSet(t *testing.T) {
	for set, cases := range map[string]map[string]bool{
		"*":                 {"0.0.1": true},
		"<2.0.0-0":          {"1.9.9": true, "2.0.0-rc.1": false},
		"<2.0.0":            {"2.0.0-rc.1": true},
		">=1.2.0 <1.3.0-0":  {"1.2.5": true, "1.3.0": false},
		"=1.0.0 || >=3.0.0": {"1.0.0": true, "2.0.0": false, "3.1.0": true},
	} {
		s := MustVersionSet(set)
		for v, want := range cases {
			pv, err := ParseVersion(v)
			must(t, err)
			if s.Contains(pv) != want {
				t.Errorf("%s contains %s != %v", set, v, want)
			}
		}
	}
	for _, bad := range []string{"", "1.0.0", ">=x", "=1.0.0 ||"} {
		if _, err := ParseVersionSet(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if (VersionSet{}).Contains(Version{}) {
		t.Error("zero set contains a version")
	}
	if err := CheckUpgradeFrom("1.0.0", MustVersionSet(">=1.9.4")); !errors.Is(err, ErrUpgradeFromRejected) {
		t.Errorf("rejected: %v", err)
	}
}

// signRaw signs a payload as written, for manifests newer than this package.
func signRaw(t *testing.T, k testKey, payload string) []byte {
	t.Helper()
	sigs, err := sign(manifestContext, []byte(payload), []ed25519.PrivateKey{k.priv})
	must(t, err)
	data, err := json.Marshal(envelope{Payload: []byte(payload), Signatures: sigs})
	must(t, err)
	return data
}

// TestForwardCompatibility walks the layers: unknown fields pass, damage stays
// in its entry, and what a client cannot use disappears by layer.
func TestForwardCompatibility(t *testing.T) {
	k := newTestKey(t)
	good := `{"name":"app","url":"a","size":1,"format":"raw","sha256":"` + zero64 + `"}`
	const head = `{"format":1,"serial":1,"product":"app","published":"2030-01-01T00:00:00Z","expires":"2031-01-01T00:00:00Z","baseline":[],"future":{"x":1},`
	open := func(body string) *Manifest {
		t.Helper()
		o, err := OpenManifest(signRaw(t, k, head+body+"}"), k.trust(), testNow)
		must(t, err)
		return o.Manifest
	}
	m := open(`"releases":[{"version":"2.0.0","new":1,"artifacts":[
		{"name":"app","url":"z","size":1,"format":"tar.zst","sha256":"` + zero64 + `"},
		{"name":"app","url":"r","size":1,"format":"raw","sha256":"` + zero64 + `","requires":["selfupdate:new"]},
		{"name":"app","size":"not a number"},
		` + good + `]},{"version":"latest","artifacts":[]},{"version":3,"artifacts":[]}]`)
	if len(m.Releases) != 1 || len(m.Releases[0].Artifacts) != 3 {
		t.Fatalf("releases %+v", m.Releases)
	}
	rt := resolve(t, m, Query{Current: "1.0.0"})
	if rt.Artifact == nil || rt.Artifact.URL != "a" {
		t.Fatalf("artifact %+v", rt.Artifact)
	}
	// A damaged rule holds, keeping what it says about how to pass.
	m = open(`"releases":[{"version":"2.0.0","artifacts":[` + good + `]}],"rules":[{"id":"d","effect":"block","when":"later","unlock":["force"],"url":"u"}]`)
	rt = resolve(t, m, Query{Current: "1.0.0"})
	if rt.Next != nil || !rt.Blocked[0].Unknown || rt.Blocked[0].URL != "u" {
		t.Fatalf("damaged rule %+v", rt)
	}
	// A condition with a new operator, too.
	m = open(`"releases":[{"version":"2.0.0","artifacts":[` + good + `]}],"rules":[{"id":"d","effect":"block","when":[{"fact":"os","glob":"*"}]}]`)
	if rt := resolve(t, m, Query{Current: "1.0.0"}); rt.Next != nil || !rt.Blocked[0].Unknown {
		t.Fatalf("new operator %+v", rt)
	}
	// A release's requirement hides it, unless a version provides it.
	m = open(`"releases":[{"version":"2.0.0","requires":["app:x"],"artifacts":[` + good + `]}]`)
	if rt := resolve(t, m, Query{Current: "1.0.0"}); rt.Next != nil || len(rt.Unusable) != 1 {
		t.Fatalf("requires %+v", rt)
	}
	if rt := resolve(t, m, Query{Current: "1.0.0", Capabilities: []string{"app:x"}}); nextOf(rt) != "2.0.0" {
		t.Fatalf("capable %+v", rt)
	}
	// The top level takes the whole manifest out.
	m = open(`"requires":["selfupdate:new"],"releases":[]`)
	if _, err := Resolve(m, Query{Current: "1.0.0"}); !errors.Is(err, ErrUnsupportedManifest) {
		t.Fatalf("top level: %v", err)
	}
	if _, err := OpenManifest(signRaw(t, k, `{"format":2}`), k.trust(), testNow); !errors.Is(err, ErrUnsupportedManifest) {
		t.Fatalf("new format: %v", err)
	}
}

// TestUpdaterRejectedRoutesOn is scenario 3: a new version refusing the source
// is final, so one Update walks down to the bridge at once instead of taking
// weeks of backing off.
func TestUpdaterRejectedRoutesOn(t *testing.T) {
	e := newUpdaterEnv(t)
	u := e.publish(t, manifestOf("app", e.release(t, "1.9.4", ""), e.release(t, "2.0.0", ""), e.release(t, "2.1.0", ""), e.release(t, "2.2.0", "")))
	var tried []string
	u.Verify = func(_ context.Context, c *Candidate, _ []string, _ io.ReaderAt) error {
		tried = append(tried, c.Version)
		if c.Version != "1.9.4" {
			return CheckUpgradeFrom(c.Current, MustVersionSet(">=1.9.4"))
		}
		return nil
	}
	plan, err := u.Update(t.Context())
	must(t, err)
	if plan.Candidate.Version != "1.9.4" || !slices.Equal(tried, []string{"2.2.0", "2.1.0", "2.0.0", "1.9.4"}) {
		t.Fatalf("plan %+v tried %v", plan.Candidate, tried)
	}
	if readFile(t, e.exe) != "app 1.9.4" {
		t.Fatal("bridge not installed")
	}
	must(t, JournalFor(e.exe).Rollback(bg))
	must(t, u.RecordOutcome(bg, Outcome{Status: StatusRolledBack, Cause: RollbackInterrupted}))
	// It does not expire, and a grant lifts it.
	u.Now = func() time.Time { return testNow.Add(20 * time.Hour) }
	if c := check(t, u); c.Version != "1.9.4" {
		t.Errorf("after a while: %s", c.Version)
	}
	u.Grants = []string{GrantRetryFailed}
	if c := check(t, u); c.Version != "2.2.0" {
		t.Errorf("retry: %s", c.Version)
	}
}

func TestUpdaterFailureMemory(t *testing.T) {
	e := newUpdaterEnv(t)
	r15, r2 := e.release(t, "1.5.0", ""), e.release(t, "2.0.0", "")
	u := e.publish(t, manifestOf("app", r15, r2))
	now := testNow
	u.Now = func() time.Time { return now }
	out := Outcome{Status: StatusRolledBack, Cause: RollbackUnconfirmed, Version: "2.0.0", Previous: "1.0.0", Digest: r2.Artifacts[0].Digest()}
	// An interrupted swap says nothing about the release.
	interrupted := out
	interrupted.Cause = RollbackInterrupted
	must(t, u.RecordOutcome(bg, interrupted))
	if c := check(t, u); c.Version != "2.0.0" {
		t.Fatalf("interrupted counted: %s", c.Version)
	}
	must(t, u.RecordOutcome(bg, out))
	if c := check(t, u); c.Version != "1.5.0" {
		t.Fatalf("not routed around: %s", c.Version)
	}
	// The wait ends, and grows with each failure up to the limit.
	now = now.Add(time.Hour)
	if c := check(t, u); c.Version != "2.0.0" {
		t.Fatalf("after the wait: %s", c.Version)
	}
	must(t, u.RecordOutcome(bg, out))
	now = now.Add(3 * time.Hour)
	if c := check(t, u); c.Version != "1.5.0" {
		t.Fatalf("second wait too short: %s", c.Version)
	}
	for _, n := range []int{1, 2, 3, 5, 50} {
		want := map[int]time.Duration{1: time.Hour, 2: 4 * time.Hour, 3: 16 * time.Hour, 5: 168 * time.Hour, 50: 168 * time.Hour}[n]
		if got := u.backoff(n); got != want {
			t.Errorf("backoff(%d) = %v", n, got)
		}
	}
	// A new artifact voids the record.
	u.Grants = nil
	r2b := e.release(t, "2.0.0", "")
	r2b.Artifacts[0].SHA256, r2b.Artifacts[0].SHA512 = strings.Repeat("a", 64), ""
	u2 := e.publish(t, manifestOf("app", r15, r2b))
	u.Sources, u2.State = u2.Sources, u.State
	if c := check(t, u); c.Version != "2.0.0" {
		t.Fatalf("new artifact: %s", c.Version)
	}
}

func TestUpdaterStaleAndSources(t *testing.T) {
	e := newUpdaterEnv(t)
	r := e.release(t, "2.0.0", "")
	old := manifestOf("app", r)
	old.Serial = 5
	newer := manifestOf("app", r, e.release(t, "3.0.0", ""))
	newer.Serial = 6
	oldURL := e.fs.put("old.json", mustSign(t, old, e.key))
	newURL := e.fs.put("new.json", mustSign(t, newer, e.key))
	u := &Updater{
		Sources: []Source{&HTTPSource{URL: newURL}}, Trust: e.key.trust(), Now: func() time.Time { return testNow },
		State: FileState(filepath.Join(t.TempDir(), "state.json")), Product: "app", Current: "1.0.0", Executable: e.exe, OS: "linux", Arch: "amd64",
	}
	if c := check(t, u); c.Version != "3.0.0" {
		t.Fatalf("newest: %s", c.Version)
	}
	u.Sources = []Source{&HTTPSource{URL: oldURL}}
	if _, err := u.Check(t.Context()); !errors.Is(err, ErrStaleManifest) {
		t.Fatalf("replay: %v", err)
	}
	// A lagging mirror is passed over.
	u.Sources = []Source{&HTTPSource{URL: oldURL}, &HTTPSource{URL: newURL}}
	if c := check(t, u); c.Version != "3.0.0" {
		t.Fatalf("mirror: %s", c.Version)
	}
	// The same serial with other content is stale as well.
	other := manifestOf("app", r)
	other.Serial = 6
	u.Sources = []Source{&HTTPSource{URL: e.fs.put("other.json", mustSign(t, other, e.key))}}
	if _, err := u.Check(t.Context()); !errors.Is(err, ErrStaleManifest) {
		t.Fatalf("same serial: %v", err)
	}
	// A manifest with no signature moves nothing.
	u.InsecureNoState = true
	u.Sources = []Source{&HTTPSource{URL: oldURL}}
	if c := check(t, u); c.Version != "2.0.0" {
		t.Fatalf("no state: %s", c.Version)
	}
}

func TestUpdaterAction(t *testing.T) {
	e := newUpdaterEnv(t)
	r := e.release(t, "2.0.0", "")
	r.Artifacts[0].Action = &Action{Kind: "handoff", Params: json.RawMessage(`{"entry":"install"}`)}
	u := e.publish(t, manifestOf("app", r))
	if p, err := u.Check(t.Context()); err != nil || p.Candidate != nil {
		t.Fatalf("unregistered action: %+v %v", p, err)
	}
	now := testNow
	u.Now = func() time.Time { return now }
	var got ActionContext
	u.Actions = map[string]ActionFunc{"handoff": func(_ context.Context, a ActionContext) (ActionResult, error) {
		got = a
		return ActionHandedOff, nil
	}}
	if _, err := u.Update(t.Context()); err != nil {
		t.Fatal(err)
	}
	if string(got.Params) != `{"entry":"install"}` || got.Artifact == nil || len(got.StateSnapshot) == 0 || readFile(t, e.exe) != "app 1.0.0" {
		t.Fatalf("action %+v", got)
	}
	if p, err := u.Check(t.Context()); err != nil || p.Route.Status != RouteHandoffPending || p.Candidate != nil {
		t.Fatalf("pending: %+v %v", p, err)
	}
	// Unconfirmed past the window counts as a failure.
	now = now.Add(2 * time.Hour)
	if p, err := u.Check(t.Context()); err != nil || p.Route.Status == RouteHandoffPending {
		t.Fatalf("after the window: %+v %v", p, err)
	}
	if p, err := u.Check(t.Context()); err != nil || p.Candidate != nil {
		t.Fatalf("failure not remembered: %+v %v", p, err)
	}
	// Confirmation and import.
	must(t, ConfirmHandoff(bg, u.State))
	fresh := FileState(filepath.Join(t.TempDir(), "state.json"))
	must(t, ImportState(bg, fresh, got.StateSnapshot))
	d, err := fresh.Load(bg)
	must(t, err)
	if d.Serial != e.serial || d.InstallID == "" {
		t.Fatalf("imported %+v", d)
	}
}

func TestStateKeepsUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	must(t, os.WriteFile(p, []byte(`{"serial":3,"from_the_future":{"a":1}}`), 0o600))
	s := FileState(p)
	must(t, s.Update(bg, func(d *StateData) error {
		return d.Advance(4, [32]byte{1})
	}))
	if data := readFile(t, p); !strings.Contains(data, "from_the_future") || !strings.Contains(data, `"serial":4`) {
		t.Fatalf("state %s", data)
	}
	must(t, os.WriteFile(p, []byte(`not json`), 0o600))
	if d, err := s.Load(bg); err != nil || d.Serial != 0 {
		t.Fatalf("damaged: %+v %v", d, err)
	}
}

func TestJournalRollbackCause(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app")
	must(t, os.WriteFile(target, []byte("old"), 0o755))
	j := JournalFor(target)
	must(t, j.Replace(bg, []Replacement{stage(t, target, "new")}, ReplaceOptions{Version: "2", Previous: "1", Digest: "d", Pending: true}))
	out, err := j.Startup(bg, 1)
	must(t, err)
	if out.Status != StatusPending || out.Digest != "d" {
		t.Fatalf("pending %+v", out)
	}
	out, err = j.Startup(bg, 1)
	must(t, err)
	if out.Status != StatusRolledBack || out.Cause != RollbackUnconfirmed || out.Digest != "d" {
		t.Fatalf("unconfirmed %+v", out)
	}
	must(t, j.Replace(bg, []Replacement{stage(t, target, "new")}, ReplaceOptions{Version: "2", Previous: "1", Pending: true}))
	st, ok, err := j.load()
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	st.Phase = phaseApplying
	must(t, j.save(&st))
	out, err = j.Startup(bg, 1)
	must(t, err)
	if out.Status != StatusRolledBack || out.Cause != RollbackInterrupted {
		t.Fatalf("interrupted %+v", out)
	}
}

func TestLintRejectsOpenPrerelease(t *testing.T) {
	open := manifestOf("app", rel("1.0.0"), rel("2.0.0-rc.1"))
	if !open.Lint(LintOptions{}).HasErrors() {
		t.Error("a pre-release without a channel must block signing")
	}
	closed := manifestOf("app", rel("1.0.0"), rel("2.0.0-rc.1"))
	closed.Releases[1].Channels = []string{"beta"}
	for _, f := range closed.Lint(LintOptions{}).Findings {
		if f.Code == "prerelease-open" {
			t.Errorf("channelled pre-release flagged: %s", f.Message)
		}
	}
}

func TestLintFindings(t *testing.T) {
	codes := func(m *Manifest, o LintOptions) []string {
		var out []string
		for _, f := range m.Lint(o).Findings {
			out = append(out, f.Code)
		}
		return out
	}
	clean := manifestOf("app", rel("1.0.0"), rel("2.0.0"))
	if got := codes(clean, LintOptions{}); len(got) != 0 {
		t.Errorf("clean: %v", got)
	}
	for want, m := range map[string]func(*Manifest){
		"prerelease-gap": func(m *Manifest) {
			m.Releases = append(m.Releases, rel("3.0.0-rc.1"))
			m.Rules = []Rule{{ID: "x", Effect: EffectBlock, To: ">=3.0.0", URL: "u"}}
		},
		"dead-end":        func(m *Manifest) { m.Rules = []Rule{{ID: "x", Effect: EffectBlock, To: ">=2.0.0-0"}} },
		"downgrade-cycle": func(m *Manifest) { m.Rules = []Rule{{ID: "x", Effect: EffectAllow, From: "=2.0.0", To: "=1.0.0"}} },
		"invalid": func(m *Manifest) {
			m.Rules = []Rule{{ID: "x", Effect: EffectBlock, When: []Condition{{Fact: "nope", In: []string{"a"}, Missing: "match"}}, URL: "u"}}
		},
		"expiry": func(m *Manifest) { m.Expires = m.Published.Add(100 * 24 * time.Hour) },
	} {
		c := manifestOf("app", rel("1.0.0"), rel("2.0.0"))
		m(c)
		if got := codes(c, LintOptions{}); !slices.Contains(got, want) {
			t.Errorf("%s not found in %v", want, got)
		}
	}
	prev := manifestOf("app", rel("1.0.0"))
	prev.Serial = 9
	if got := codes(clean, LintOptions{Previous: prev}); !slices.Contains(got, "serial") {
		t.Errorf("serial: %v", got)
	}
	if rep := clean.Lint(LintOptions{Budget: 1}); rep.Coverage.Exhausted || rep.Coverage.Combinations != 1 {
		t.Errorf("budget: %+v", rep.Coverage)
	}
}
