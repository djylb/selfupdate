package selfupdate

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The levels of a [Finding].
const (
	LintError = "error"
	LintWarn  = "warn"
)

const (
	defaultLintBudget = 1_000_000
	maxExpiryAdvice   = 45 * 24 * time.Hour
	serialJumpAdvice  = 1 << 32
)

// Finding is one problem [Manifest.Lint] found.
type Finding struct {
	// Level is [LintError] or [LintWarn].
	Level string
	// Code names the check.
	Code string
	// Message explains the problem.
	Message string
}

// Coverage says how much of the declared input space was walked. It covers the
// declared dimensions only, so a clean report is no proof of correctness.
type Coverage struct {
	// Unverified lists what was not enumerated.
	Unverified []string
	// Combinations counts the inputs walked.
	Combinations int
	// Exhausted says every declared combination was walked within the budget.
	Exhausted bool
}

// LintOptions configures [Manifest.Lint].
type LintOptions struct {
	// Previous is the manifest this one follows, if any.
	Previous *Manifest
	// Capabilities is the client to judge for, beyond [LibraryCapabilities].
	Capabilities []string
	// Budget bounds the combinations walked; zero means one million.
	Budget int
	// MaxSize is the largest encoded manifest clients accept; zero means 1 MiB.
	MaxSize int64
}

// LintReport is the result of [Manifest.Lint].
type LintReport struct {
	// Findings lists the problems.
	Findings []Finding
	// Coverage says what was walked.
	Coverage Coverage
}

// HasErrors reports whether any finding is an error.
func (r LintReport) HasErrors() bool {
	return slices.ContainsFunc(r.Findings, func(f Finding) bool { return f.Level == LintError })
}

// SimOptions configures [Manifest.Simulate].
type SimOptions struct {
	// Capabilities is the client to judge for, beyond [LibraryCapabilities].
	Capabilities []string
	// Budget bounds the combinations walked; zero means one million.
	Budget int
}

// RouteRow is one line of [Manifest.Simulate].
type RouteRow struct {
	// Facts holds the fact values of this line.
	Facts map[string][]string
	// From is the source version; Next, Goal, Horizon and Latest come from the
	// route.
	From, Next, Goal, Horizon, Latest string
	// OS, Arch and Name are the platform and artifact.
	OS, Arch, Name string
	// Grants lists what the caller held.
	Grants []string
	// Blocked explains the edge from Goal to Latest.
	Blocked []Reason
}

// boundaries lists the versions a set compares with.
func (s VersionSet) boundaries() []setClause {
	var out []setClause
	for _, g := range s.groups {
		out = append(out, g...)
	}
	return out
}

func (m *Manifest) allRules() []*Rule {
	out := make([]*Rule, 0, len(m.Baseline)+len(m.Rules))
	for i := range m.Baseline {
		out = append(out, &m.Baseline[i])
	}
	for i := range m.Rules {
		out = append(out, &m.Rules[i])
	}
	return out
}

func (m *Manifest) ruleSets(r *Rule) []VersionSet {
	var out []VersionSet
	for _, s := range []string{r.From, r.To} {
		if set, err := ParseVersionSet(s); err == nil {
			out = append(out, set)
		}
	}
	return out
}

// simFroms lists source versions, one for each region the rules tell apart.
func (m *Manifest) simFroms() []Version {
	vs := []Version{{}}
	add := func(v Version) {
		vs = append(vs, v, Version{Major: v.Major, Minor: v.Minor, Patch: v.Patch + 1})
	}
	for i := range m.Releases {
		if v, err := ParseVersion(m.Releases[i].Version); err == nil {
			add(v)
		}
	}
	for _, r := range m.allRules() {
		for _, s := range m.ruleSets(r) {
			for _, c := range s.boundaries() {
				add(c.v)
			}
		}
	}
	slices.SortFunc(vs, Version.Compare)
	return slices.CompactFunc(vs, func(a, b Version) bool { return a.Compare(b) == 0 })
}

type simPlatform struct{ os, arch, name string }

func (m *Manifest) simPlatforms() []simPlatform {
	var out []simPlatform
	for i := range m.Releases {
		for _, a := range m.Releases[i].Artifacts {
			p := simPlatform{cmpOr(a.OS, "other"), cmpOr(a.Arch, "other"), a.Name}
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	// Values only rules name are tried too, with a value outside them for rules
	// that negate.
	named := map[string]map[string]bool{"os": {}, "arch": {}, "name": {}}
	for _, r := range m.allRules() {
		for i := range r.When {
			if c := &r.When[i]; named[c.Fact] != nil {
				for _, v := range c.In {
					named[c.Fact][v] = true
				}
			}
		}
	}
	if len(named["os"])+len(named["arch"])+len(named["name"]) > 0 {
		for _, p := range out {
			named["os"][p.os], named["arch"][p.arch], named["name"][p.name] = true, true, true
		}
		named["os"]["other"], named["arch"]["other"] = true, true
		out = nil
		for os := range named["os"] {
			for arch := range named["arch"] {
				for name := range named["name"] {
					out = append(out, simPlatform{os, arch, name})
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b simPlatform) int {
		return strings.Compare(a.os+"/"+a.arch+"/"+a.name, b.os+"/"+b.arch+"/"+b.name)
	})
	return out
}

func cmpOr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

// simGrants lists the grant sets worth trying: none, all, and each alone.
func (m *Manifest) simGrants() [][]string {
	all := map[string]bool{GrantRollout: true}
	for _, r := range m.allRules() {
		for _, g := range r.Unlock {
			all[g] = true
		}
	}
	for i := range m.Releases {
		for _, c := range m.Releases[i].Channels {
			all[grantChannelPrefix+c] = true
		}
	}
	names := make([]string, 0, len(all))
	for g := range all {
		names = append(names, g)
	}
	slices.Sort(names)
	out := [][]string{nil, names}
	for _, g := range names {
		out = append(out, []string{g})
	}
	return out
}

// simFacts lists the values to try per fact, and the facts that cannot be
// enumerated.
func (m *Manifest) simFacts() (names []string, values [][][]string, unverified []string) {
	for name := range m.Facts {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		f := m.Facts[name]
		vals := [][]string{nil}
		switch {
		case f.Type == "version":
			seen := map[string]bool{}
			for _, r := range m.allRules() {
				for i := range r.When {
					if c := &r.When[i]; c.Fact == name && c.Range != "" {
						if set, err := ParseVersionSet(c.Range); err == nil {
							for _, b := range set.boundaries() {
								seen[b.v.String()] = true
								seen[Version{Major: b.v.Major, Minor: b.v.Minor, Patch: b.v.Patch + 1}.String()] = true
							}
						}
					}
				}
			}
			keys := make([]string, 0, len(seen))
			for k := range seen {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				vals = append(vals, []string{k})
			}
		case len(f.Domain) > 0:
			for _, d := range f.Domain {
				vals = append(vals, []string{d})
			}
			vals = append(vals, []string{"other"})
		default:
			unverified = append(unverified, "fact "+name+" has no domain")
		}
		values = append(values, vals)
	}
	return names, values, unverified
}

// Simulate walks the declared dimensions and returns the route of each
// combination, for reviewing a manifest before signing it. Failure records,
// local rules and facts without a domain are not enumerated. A walk that hits
// the budget says so in the coverage instead of sampling silently.
func (m *Manifest) Simulate(o SimOptions) ([]RouteRow, Coverage) {
	budget := o.Budget
	if budget <= 0 {
		budget = defaultLintBudget
	}
	names, values, unverified := m.simFacts()
	cov := Coverage{Exhausted: true, Unverified: append(unverified, "failure records", "local rules", "clock")}
	var rows []RouteRow
	froms, platforms, grants := m.simFroms(), m.simPlatforms(), m.simGrants()
	idx := make([]int, len(names))
	for {
		facts := map[string][]string{}
		for i, n := range names {
			if v := values[i][idx[i]]; v != nil {
				facts[n] = v
			}
		}
		for _, from := range froms {
			for _, p := range platforms {
				for _, g := range grants {
					if cov.Combinations >= budget {
						cov.Exhausted = false
						return rows, cov
					}
					cov.Combinations++
					rt, err := Resolve(m, Query{
						Current: from.String(), OS: p.os, Arch: p.arch, Name: p.name,
						Facts: facts, Grants: g, Capabilities: o.Capabilities,
					})
					if err != nil {
						continue
					}
					row := RouteRow{
						Facts: facts, From: from.String(), Goal: rt.Goal, Horizon: rt.Horizon, Latest: rt.Latest,
						OS: p.os, Arch: p.arch, Name: p.name, Grants: g, Blocked: rt.Blocked,
					}
					if rt.Next != nil {
						row.Next = rt.Next.Version
					}
					rows = append(rows, row)
				}
			}
		}
		i := len(idx) - 1
		for ; i >= 0; i-- {
			idx[i]++
			if idx[i] < len(values[i]) {
				break
			}
			idx[i] = 0
		}
		if i < 0 {
			return rows, cov
		}
	}
}

// Lint checks a manifest for mistakes a publisher can make with valid syntax.
func (m *Manifest) Lint(o LintOptions) LintReport {
	var rep LintReport
	add := func(level, code, format string, args ...any) {
		rep.Findings = append(rep.Findings, Finding{Level: level, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	if err := m.validate(); err != nil {
		add(LintError, "invalid", "%v", err)
	}
	m.lintSize(add, o)
	m.lintRules(add)
	m.lintReleases(add)
	m.lintPrevious(add, o)
	rows, cov := m.Simulate(SimOptions{Capabilities: o.Capabilities, Budget: o.Budget})
	rep.Coverage = cov
	seen := map[string]bool{}
	allGrants := len(m.simGrants()[1])
	for i := range rows {
		row := &rows[i]
		if row.Goal == row.Latest || len(row.Grants) != allGrants {
			continue
		}
		for _, b := range row.Blocked {
			key := b.RuleID + "/" + b.Code
			if b.URL != "" || b.Kind == ReasonCapability || b.Kind == ReasonRollout || seen[key] {
				continue
			}
			seen[key] = true
			add(LintError, "dead-end", "%s on %s/%s stops at %s below %s, held by %q with no url", row.From, row.OS, row.Arch, row.Goal, row.Latest, b.RuleID)
		}
	}
	if !cov.Exhausted {
		add(LintWarn, "not-exhausted", "stopped after %d combinations", cov.Combinations)
	}
	return rep
}

type lintAdd func(level, code, format string, args ...any)

func (m *Manifest) lintSize(add lintAdd, o LintOptions) {
	limit := o.MaxSize
	if limit <= 0 {
		limit = 1 << 20
	}
	data, err := json.Marshal(m)
	// The payload travels in base64, which grows it by a third.
	if err == nil && int64(len(data))*4/3 > limit {
		add(LintError, "size", "about %d bytes when signed, clients accept %d", int64(len(data))*4/3, limit)
	}
	if !m.Published.IsZero() && m.Expires.Sub(m.Published) > maxExpiryAdvice {
		add(LintWarn, "expiry", "valid for %s: a frozen mirror goes unnoticed for that long", m.Expires.Sub(m.Published))
	}
}

func (m *Manifest) lintRules(add lintAdd) {
	var releases []Version
	for i := range m.Releases {
		if v, err := ParseVersion(m.Releases[i].Version); err == nil {
			releases = append(releases, v)
		}
	}
	for _, r := range m.allRules() {
		// Boundaries that leave out the pre-releases of a version.
		for _, set := range m.ruleSets(r) {
			for _, c := range set.boundaries() {
				if c.op == opEq || c.v.IsPrerelease() {
					continue
				}
				gap := slices.ContainsFunc(releases, func(v Version) bool {
					return v.IsPrerelease() && v.Major == c.v.Major && v.Minor == c.v.Minor && v.Patch == c.v.Patch
				})
				if gap {
					add(LintError, "prerelease-gap", "rule %s: %s misses a listed pre-release, write %s-0", r.ID, set, c.v)
				} else {
					add(LintWarn, "prerelease-gap", "rule %s: %s would miss pre-releases, write %s-0", r.ID, set, c.v)
				}
			}
		}
		if r.Effect == EffectBlock && r.To == "" && r.IfUnknown != "ignore" && len(r.Requires) > 0 && len(r.Unlock) == 0 {
			add(LintError, "stuck-old-clients", "rule %s: a client not knowing it can never update", r.ID)
		}
		if r.Effect == EffectBlock && len(r.Unlock) == 0 && r.URL == "" {
			add(LintWarn, "no-url", "rule %s: closes edges for good and gives no url", r.ID)
		}
		from, _ := parseOrAll(r.From)
		for i := range r.When {
			c := &r.When[i]
			if !isBuiltinFact(c.Fact) && !m.Facts[c.Fact].Stable && c.Missing == "match" && r.Effect == EffectBlock && !hasUpperBound(from) {
				add(LintWarn, "gate-reopens", "rule %s: versions that stop reporting %s are held again; give from an upper bound", r.ID, c.Fact)
			}
		}
		if r.Effect == EffectAllow {
			m.lintCycle(add, r, releases)
		}
	}
}

func hasUpperBound(s VersionSet) bool {
	if len(s.groups) == 0 {
		return false
	}
	for _, g := range s.groups {
		if !slices.ContainsFunc(g, func(c setClause) bool { return c.op == opLt || c.op == opLe || c.op == opEq }) {
			return false
		}
	}
	return true
}

// lintCycle reports a downgrade whose target would update right back.
func (m *Manifest) lintCycle(add lintAdd, allow *Rule, releases []Version) {
	from, _ := parseOrAll(allow.From)
	to, _ := parseOrAll(allow.To)
	for _, x := range releases {
		for _, w := range releases {
			if !from.Contains(x) || !to.Contains(w) || w.Compare(x) >= 0 {
				continue
			}
			held := slices.ContainsFunc(m.allRules(), func(r *Rule) bool {
				f, _ := parseOrAll(r.From)
				t, _ := parseOrAll(r.To)
				return r.Effect == EffectBlock && f.Contains(w) && t.Contains(x)
			})
			if !held {
				add(LintError, "downgrade-cycle", "rule %s: %s goes back to %s, which updates to %s again", allow.ID, x, w, x)
			}
		}
	}
}

func (m *Manifest) lintReleases(add lintAdd) {
	for i := range m.Releases {
		r := &m.Releases[i]
		if len(r.Provides) > 0 && !slices.ContainsFunc(r.Provides, func(c string) bool { return strings.HasPrefix(c, "format:") }) {
			add(LintWarn, "provides-partial", "release %s: provides must be the complete set; it lists no format", r.Version)
		}
		if v, err := ParseVersion(r.Version); err == nil && v.IsPrerelease() && len(r.Channels) == 0 {
			add(LintError, "prerelease-open", "release %s: a pre-release without a channel reaches everyone", r.Version)
		}
		for j := range r.Artifacts {
			a := &r.Artifacts[j]
			for _, o := range r.Artifacts[:j] {
				if o.Name == a.Name && overlaps(o.OS, a.OS) && overlaps(o.Arch, a.Arch) && len(o.Requires) == 0 && o.Format == a.Format {
					add(LintWarn, "shadowed", "release %s: artifact %s is never chosen", r.Version, a.URL)
				}
			}
		}
	}
}

func (m *Manifest) lintPrevious(add lintAdd, o LintOptions) {
	p := o.Previous
	if p == nil {
		return
	}
	if m.Serial <= p.Serial {
		add(LintError, "serial", "serial %d does not grow from %d", m.Serial, p.Serial)
	} else if m.Serial-p.Serial > serialJumpAdvice {
		add(LintWarn, "serial-jump", "serial jumps from %d to %d", p.Serial, m.Serial)
	}
	old := map[string]*Rule{}
	for _, r := range p.allRules() {
		old[r.ID] = r
	}
	for _, r := range m.allRules() {
		before, ok := old[r.ID]
		if !ok {
			if r.Effect == EffectBlock && len(r.Unlock) == 0 {
				add(LintWarn, "new-gate", "rule %s: new gate no grant lifts", r.ID)
			}
			continue
		}
		if slices.Contains(r.Unlock, "accept:"+r.ID) {
			a, _ := json.Marshal(before)
			b, _ := json.Marshal(r)
			if string(a) != string(b) {
				add(LintError, "accept-changed", "rule %s changed but keeps its id: earlier acceptance would carry over", r.ID)
			}
		}
	}
	oldRows, _ := p.Simulate(SimOptions{Capabilities: o.Capabilities, Budget: o.Budget})
	newRows, _ := m.Simulate(SimOptions{Capabilities: o.Capabilities, Budget: o.Budget})
	goals := map[string]string{}
	key := func(r *RouteRow) string {
		f, _ := json.Marshal(r.Facts)
		return r.From + "|" + r.OS + "|" + r.Arch + "|" + r.Name + "|" + strings.Join(r.Grants, ",") + "|" + string(f)
	}
	for i := range oldRows {
		goals[key(&oldRows[i])] = oldRows[i].Goal
	}
	for i := range newRows {
		before, ok := goals[key(&newRows[i])]
		if !ok {
			continue
		}
		if c, err := CompareVersions(newRows[i].Goal, before); err == nil && c < 0 {
			add(LintWarn, "goal-lower", "%s on %s/%s: goal falls from %s to %s", newRows[i].From, newRows[i].OS, newRows[i].Arch, before, newRows[i].Goal)
			return
		}
	}
}

func overlaps(a, b string) bool { return a == "" || b == "" || a == b }
