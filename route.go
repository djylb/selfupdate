package selfupdate

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const actionReplace = "replace"

// The effects of a [Rule].
const (
	EffectBlock  = "block"
	EffectAllow  = "allow"
	EffectNotice = "notice"
)

// The grants this package itself gives a meaning to. Grants are open strings:
// a rule may name any other, such as "accept:<rule-id>" or "user".
const (
	GrantForce           = "force"
	GrantRollout         = "rollout"
	GrantDowngradeAny    = "downgrade:any"
	GrantDowngradeOffer  = "downgrade:offered"
	GrantReinstall       = "reinstall"
	GrantRetryFailed     = "retry-failed"
	grantChannelPrefix   = "channel:"
	reasonDowngrade      = "downgrade"
	reasonReinstall      = "reinstall"
	reasonRollout        = "rollout"
	reasonPaused         = "paused"
	reasonFailed         = "failed"
	reasonNoArtifact     = "no-artifact"
	reasonMissingCapable = "missing-capability"
)

// Fact declares a fact rules may ask about. A stable fact keeps its value when
// the program is updated, so it can be judged for future edges as well.
type Fact struct {
	// Type is "version" for facts compared with a range.
	Type string `json:"type,omitempty"`
	// Domain lists the possible values, for exhaustive linting.
	Domain []string `json:"domain,omitempty"`
	// Stable says the value survives an update.
	Stable bool `json:"stable,omitempty"`
}

// Condition is one test of a rule on a fact. It has exactly one operator:
// In or Range. A condition with no known operator makes its rule unknown, which
// is how new operators stay safe for old clients.
type Condition struct {
	// Fact names the fact.
	Fact string `json:"fact"`
	// Range tests values as versions; see [ParseVersionSet].
	Range string `json:"range,omitempty"`
	// Quant is "any" (default) or "all", for facts with several values.
	Quant string `json:"quant,omitempty"`
	// Missing says what a fact without a value means, "match" or "nomatch".
	// It is mandatory for facts that are not built in, and not affected by
	// Negate.
	Missing string `json:"missing,omitempty"`
	// In tests values for equality.
	In []string `json:"in,omitempty"`
	// Negate inverts the test.
	Negate bool `json:"negate,omitempty"`
}

// Rule changes the implicit graph of upgrades. A block closes the edges it
// matches unless the caller holds one of Unlock; an allow cancels baseline gates
// and offers downgrades; a notice only informs and never affects routing.
type Rule struct {
	// ID identifies the rule, unique within the manifest. Local rules have
	// their own name space.
	ID string `json:"id"`
	// Effect is [EffectBlock], [EffectAllow] or [EffectNotice].
	Effect string `json:"effect"`
	// From and To are version sets, see [ParseVersionSet]; empty means all.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// IfUnknown says what a client that does not understand the rule does:
	// "block" (default) or "ignore".
	IfUnknown string `json:"if_unknown,omitempty"`
	// Reason is an open code passed through to the caller.
	Reason string `json:"reason,omitempty"`
	// Class is the kind of a notice, open.
	Class string `json:"class,omitempty"`
	// Message and URL are for humans.
	Message string `json:"message,omitempty"`
	URL     string `json:"url,omitempty"`
	// When holds conditions that must all be true.
	When []Condition `json:"when,omitempty"`
	// Unlock lists the grants that lift a block; empty means none does.
	Unlock []string `json:"unlock,omitempty"`
	// Requires lists capabilities needed to understand the rule.
	Requires []string `json:"requires,omitempty"`
	// Attrs is passed through to the caller.
	Attrs json.RawMessage `json:"attrs,omitempty"`
	// kind overrides the reported kind of an internal local rule.
	kind ReasonKind
	// damaged marks a rule that could not be decoded.
	damaged bool
}

// Query is what [Resolve] judges a manifest for. It holds every input: Resolve
// has no clock, no I/O and no callbacks, so equal inputs give equal routes.
type Query struct {
	// Current is the running version. Name, OS and Arch select the artifact.
	Current, Name, OS, Arch string
	// Target asks for a specific version instead of the highest.
	Target string
	// InstallID places the installation in rollouts; without it only complete
	// rollouts are seen.
	InstallID string
	// Facts holds the facts of this installation, several values allowed.
	Facts map[string][]string
	// Grants lists what the caller accepts.
	Grants []string
	// Capabilities lists what this program can do beyond
	// [LibraryCapabilities].
	Capabilities []string
	// LocalRules are the caller's own rules, which can only tighten: a block
	// or a notice. Anything else makes Resolve fail.
	LocalRules []Rule
}

// RouteStatus says what a [Route] offers.
type RouteStatus int

const (
	// RouteCurrent means nothing newer exists.
	RouteCurrent RouteStatus = iota
	// RouteAvailable means Route.Next can be installed.
	RouteAvailable
	// RouteHeld means newer versions exist and none can be installed now.
	RouteHeld
	// RouteHandoffPending means an action handed the update to an installer
	// whose result is not known yet.
	RouteHandoffPending
)

// ReasonKind says where a [Reason] comes from.
type ReasonKind int

// The kinds of reasons.
const (
	ReasonRule ReasonKind = iota
	ReasonBaseline
	ReasonLocal
	ReasonRollout
	ReasonFailed
	ReasonCapability
	ReasonDowngrade
)

// Reason explains one closed edge or unusable release.
type Reason struct {
	// RuleID names the rule, if one is behind it.
	RuleID string
	// Code is the rule's reason, or a built-in code.
	Code string
	// Message and URL are for humans.
	Message, URL string
	// Target is the version the edge leads to.
	Target string
	// Unlock lists the grants any of which lifts it.
	Unlock []string
	// Attrs is the rule's attrs.
	Attrs json.RawMessage
	// Kind says where it comes from.
	Kind ReasonKind
	// Unknown marks a rule this client does not understand.
	Unknown bool
}

// Notice is an informational rule that applies to the running version.
type Notice struct {
	// RuleID, Class, Message and URL come from the rule.
	RuleID, Class, Message, URL string
	// Attrs comes from the rule.
	Attrs json.RawMessage
	// Reachable says whether Goal is in the rule's To.
	Reachable bool
}

// Hop is one step of a [Route].
type Hop struct {
	// Version is where the step leads.
	Version string
	// Predicted says the step depends on something that can change until the
	// client gets there.
	Predicted bool
}

// Offer is a first step the caller could take with more grants.
type Offer struct {
	// Version is the release on offer.
	Version string
	// Reasons explains what holds it.
	Reasons []Reason
	// Needs lists one grant for each thing holding it.
	Needs []string
}

// Route is the result of [Resolve].
type Route struct {
	// Next is the release to install now, nil if none.
	Next *Release
	// Artifact is the artifact of Next.
	Artifact *Artifact
	// Current is the running version.
	Current string
	// Goal is the highest version reachable for certain; Horizon the highest
	// reachable if everything uncertain on the way opens up. Latest is the
	// highest visible version.
	Goal, Horizon, Latest string
	// Path is the expected way from here to Horizon, starting with Next.
	Path []Hop
	// Offers lists first steps open to more grants.
	Offers []Offer
	// Blocked explains the edge from Goal to Latest.
	Blocked []Reason
	// Unusable lists newer releases this client cannot use at all.
	Unusable []Reason
	// Notices lists notices for the running version.
	Notices []Notice
	// Forced lists the rules a grant lifted on the way to Next.
	Forced []string
	// Status says what the route offers.
	Status RouteStatus
	// Downgrade and Reinstall say Next is not a newer version.
	Downgrade, Reinstall bool
}

// LibraryCapabilities returns the capabilities of this package: the formats,
// digests and actions it handles. A release's Provides is its complete set,
// so a build exports these together with its own.
func LibraryCapabilities() []string {
	return []string{
		"action:" + actionReplace, "digest:sha256", "digest:sha512",
		"format:gz", "format:raw", "format:tar", "format:tar.gz", "format:zip",
	}
}

func isBuiltinFact(name string) bool {
	switch name {
	case "os", "arch", "name", "to.label", "edge.crosses":
		return true
	}
	return false
}

// checkRule reports why r cannot be understood. It looks at the structure
// only; capabilities are the caller's to check.
func (m *Manifest) checkRule(r *Rule, local bool) error {
	switch {
	case r.damaged:
		return errors.New("damaged")
	case r.Effect != EffectBlock && r.Effect != EffectAllow && r.Effect != EffectNotice:
		return fmt.Errorf("unknown effect %q", r.Effect)
	case local && r.Effect == EffectAllow:
		return errors.New("a local rule cannot allow")
	case r.IfUnknown != "" && r.IfUnknown != "block" && r.IfUnknown != "ignore":
		return fmt.Errorf("unknown if_unknown %q", r.IfUnknown)
	}
	for _, s := range []string{r.From, r.To} {
		if s != "" {
			if _, err := ParseVersionSet(s); err != nil {
				return err
			}
		}
	}
	for i := range r.When {
		c := &r.When[i]
		if (len(c.In) > 0) == (c.Range != "") {
			return fmt.Errorf("fact %s: needs exactly one known operator", c.Fact)
		}
		if c.Range != "" {
			if _, err := ParseVersionSet(c.Range); err != nil {
				return err
			}
		}
		if c.Quant != "" && c.Quant != "any" && c.Quant != "all" {
			return fmt.Errorf("fact %s: unknown quant %q", c.Fact, c.Quant)
		}
		if isBuiltinFact(c.Fact) {
			if c.Range != "" {
				return fmt.Errorf("fact %s: is not a version", c.Fact)
			}
			continue
		}
		f, declared := Fact{}, false
		if m != nil {
			f, declared = m.Facts[c.Fact]
		}
		switch {
		case !local && !declared:
			return fmt.Errorf("fact %s: not declared", c.Fact)
		case c.Missing != "match" && c.Missing != "nomatch":
			return fmt.Errorf("fact %s: missing must be match or nomatch", c.Fact)
		case !local && c.Range != "" && f.Type != "version":
			return fmt.Errorf("fact %s: range needs type version", c.Fact)
		}
	}
	return nil
}

type hitState int

const (
	hitNo hitState = iota
	hitMaybe
	hitYes
)

type edgeState int

const (
	edgeOpen edgeState = iota
	edgePredicted
	edgeClosed
)

type usableState int

const (
	usableNo usableState = iota
	usableUnknown
	usableYes
)

type compiledCond struct {
	in      map[string]bool
	rng     VersionSet
	cond    *Condition
	builtin bool
	stable  bool
	isRange bool
}

type compiledRule struct {
	from, to VersionSet
	r        *Rule
	conds    []compiledCond
	kind     ReasonKind
	hasTo    bool
	unknown  bool
}

type node struct {
	rel     *Release
	caps    map[string]bool
	v       Version
	capsSet bool
}

type engine struct {
	grants, caps map[string]bool
	m            *Manifest
	q            *Query
	allows       []*compiledRule
	baseline     []*compiledRule
	blocks       []*compiledRule
	notices      []*compiledRule
	nodes        []*node
	judged       map[[2]*node]judged
	cur          int
}

// Resolve chooses where to go from q.Current. It is a pure function of its
// inputs and judges every first step for certain, using all of q; later steps
// can only use what will still hold then, so they may be predictions.
func Resolve(m *Manifest, q Query) (*Route, error) {
	e, err := newEngine(m, &q)
	if err != nil {
		return nil, err
	}
	return e.route()
}

func toSet(ss ...[]string) map[string]bool {
	out := map[string]bool{}
	for _, s := range ss {
		for _, v := range s {
			out[v] = true
		}
	}
	return out
}

func newEngine(m *Manifest, q *Query) (*engine, error) {
	cur, err := ParseVersion(q.Current)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: current version %q: %w", q.Current, err)
	}
	e := &engine{m: m, q: q, grants: toSet(q.Grants), caps: toSet(q.Capabilities, LibraryCapabilities())}
	for _, c := range m.Requires {
		if !e.caps[c] {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedManifest, c)
		}
	}
	for i := range q.LocalRules {
		r := &q.LocalRules[i]
		if err := m.checkRule(r, true); err != nil {
			return nil, fmt.Errorf("selfupdate: local rule %q: %w", r.ID, err)
		}
		kind := r.kind
		if kind == ReasonRule {
			kind = ReasonLocal
		}
		e.add(r, kind, true)
	}
	for i := range m.Baseline {
		e.add(&m.Baseline[i], ReasonBaseline, false)
	}
	for i := range m.Rules {
		e.add(&m.Rules[i], ReasonRule, false)
	}
	current := &node{v: cur, caps: e.caps, capsSet: true}
	e.nodes = append(e.nodes, current)
	for i := range m.Releases {
		r := &m.Releases[i]
		if !e.visible(r) {
			continue
		}
		v, err := ParseVersion(r.Version)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrMalformedManifest, r.Version, err)
		}
		if v.Compare(cur) == 0 {
			current.rel = r
			continue
		}
		e.nodes = append(e.nodes, &node{rel: r, v: v, caps: toSet(r.Provides), capsSet: len(r.Provides) > 0})
	}
	slices.SortFunc(e.nodes, func(a, b *node) int { return a.v.Compare(b.v) })
	e.cur = slices.Index(e.nodes, current)
	return e, nil
}

func (e *engine) visible(r *Release) bool {
	if len(r.Channels) == 0 {
		return true
	}
	return slices.ContainsFunc(r.Channels, func(c string) bool { return e.grants[grantChannelPrefix+c] })
}

func parseOrAll(s string) (VersionSet, bool) {
	if s != "" {
		if set, err := ParseVersionSet(s); err == nil {
			return set, true
		}
	}
	return MustVersionSet("*"), false
}

// add compiles a rule. A rule that cannot be understood becomes an unknown
// block (or nothing, as it asks); a notice never does, since it must not
// affect routing.
func (e *engine) add(r *Rule, kind ReasonKind, local bool) {
	unknown := e.m.checkRule(r, local) != nil
	for _, c := range r.Requires {
		unknown = unknown || !e.caps[c]
	}
	if unknown && (r.IfUnknown == "ignore" || r.Effect == EffectNotice) {
		return
	}
	cr := &compiledRule{r: r, kind: kind, unknown: unknown}
	cr.from, _ = parseOrAll(r.From)
	cr.to, cr.hasTo = parseOrAll(r.To)
	if unknown {
		e.blocks = append(e.blocks, cr)
		return
	}
	for i := range r.When {
		c := &r.When[i]
		cc := compiledCond{cond: c, builtin: isBuiltinFact(c.Fact), stable: isBuiltinFact(c.Fact) || e.m.Facts[c.Fact].Stable}
		if c.Range != "" {
			cc.rng, cc.isRange = MustVersionSet(c.Range), true
		} else {
			cc.in = toSet(c.In)
		}
		cr.conds = append(cr.conds, cc)
	}
	switch {
	case r.Effect == EffectNotice:
		e.notices = append(e.notices, cr)
	case r.Effect == EffectAllow:
		e.allows = append(e.allows, cr)
	case kind == ReasonBaseline:
		e.baseline = append(e.baseline, cr)
	default:
		e.blocks = append(e.blocks, cr)
	}
}

func crosses(u, t Version) string {
	switch {
	case u.Major != t.Major:
		return "major"
	case u.Minor != t.Minor:
		return "minor"
	case u.Patch != t.Patch:
		return "patch"
	}
	return "none"
}

func (e *engine) values(fact string, u, t *node) []string {
	switch fact {
	case "os":
		return []string{e.q.OS}
	case "arch":
		return []string{e.q.Arch}
	case "name":
		return []string{e.q.Name}
	case "to.label":
		if t != nil && t.rel != nil {
			return t.rel.Labels
		}
		return nil
	case "edge.crosses":
		if t != nil {
			return []string{crosses(u.v, t.v)}
		}
		return []string{"none"}
	}
	return e.q.Facts[fact]
}

func (cc *compiledCond) test(values []string) bool {
	if cc.builtin && len(values) == 0 {
		return cc.cond.Negate
	}
	if len(values) == 0 {
		return cc.cond.Missing == "match"
	}
	one := func(s string) bool {
		if cc.isRange {
			v, err := ParseVersion(s)
			return err == nil && cc.rng.Contains(v)
		}
		return cc.in[s]
	}
	var ok bool
	if cc.cond.Quant == "all" {
		ok = !slices.ContainsFunc(values, func(s string) bool { return !one(s) })
	} else {
		ok = slices.ContainsFunc(values, one)
	}
	return ok != cc.cond.Negate
}

// hit evaluates the conditions of a rule on an edge; future says that facts
// that do not survive an update cannot be judged.
func (e *engine) hit(cr *compiledRule, u, t *node, future bool) hitState {
	if !cr.from.Contains(u.v) || (t != nil && !cr.to.Contains(t.v)) {
		return hitNo
	}
	out := hitYes
	for i := range cr.conds {
		cc := &cr.conds[i]
		if future && !cc.stable {
			out = hitMaybe
			continue
		}
		if !cc.test(e.values(cc.cond.Fact, u, t)) {
			return hitNo
		}
	}
	return out
}

func (cr *compiledRule) reason(t *node) Reason {
	code := cr.r.Reason
	return Reason{
		RuleID: cr.r.ID, Code: code, Message: cr.r.Message, URL: cr.r.URL, Unlock: slices.Clone(cr.r.Unlock),
		Target: t.v.String(), Attrs: cr.r.Attrs, Kind: cr.kind, Unknown: cr.unknown,
	}
}

// bucket places an installation in a release's rollout.
func bucket(installID, product, version string) int {
	sum := sha256.Sum256([]byte(installID + "\x00" + product + "\x00" + version))
	return int(binary.BigEndian.Uint64(sum[:8]) % 100)
}

// edge judges the edge from u to t. A first edge (u is current) is decided for
// certain from all inputs; a future edge may be open only as a prediction.
func (e *engine) edge(u, t *node) (edgeState, []Reason, []string) {
	first := u == e.nodes[e.cur]
	future := !first
	state := edgeOpen
	var held []Reason
	var forced []string
	gate := func(rs Reason, certain bool) {
		if first {
			for _, g := range rs.Unlock {
				if e.grants[g] {
					if rs.RuleID != "" {
						forced = append(forced, rs.RuleID)
					}
					return
				}
			}
			state = edgeClosed
			held = append(held, rs)
			return
		}
		held = append(held, rs)
		if certain && len(rs.Unlock) == 0 {
			state = edgeClosed
		} else if state == edgeOpen {
			state = edgePredicted
		}
	}
	allow := hitNo
	for _, cr := range e.allows {
		allow = max(allow, e.hit(cr, u, t, future))
	}
	for _, cr := range e.baseline {
		h := e.hit(cr, u, t, future)
		if h == hitNo || allow == hitYes {
			continue
		}
		gate(cr.reason(t), h == hitYes && allow == hitNo)
	}
	for _, cr := range e.blocks {
		h := e.hit(cr, u, t, future)
		if h != hitNo {
			gate(cr.reason(t), h == hitYes && !cr.unknown)
		}
	}
	order := t.v.Compare(u.v)
	switch {
	case order < 0:
		unlock := []string{GrantDowngradeAny}
		if allow == hitYes {
			unlock = append(unlock, GrantDowngradeOffer)
		}
		gate(Reason{Code: reasonDowngrade, Target: t.v.String(), Unlock: unlock, Kind: ReasonDowngrade}, true)
	case order == 0:
		gate(Reason{Code: reasonReinstall, Target: t.v.String(), Unlock: []string{GrantReinstall}, Kind: ReasonDowngrade}, true)
	}
	if t.rel != nil && t.rel.Rollout != nil {
		ro := t.rel.Rollout
		switch {
		case ro.Paused:
			rs := Reason{Code: reasonPaused, Target: t.v.String(), Kind: ReasonRollout}
			gate(rs, first)
		case ro.Percent < 100 && (e.q.InstallID == "" || bucket(e.q.InstallID, e.m.Product, t.v.String()) >= ro.Percent):
			gate(Reason{Code: reasonRollout, Target: t.v.String(), Unlock: []string{GrantRollout}, Kind: ReasonRollout}, false)
		}
	}
	return state, held, forced
}

func (a *Artifact) matches(name, goos, goarch string) bool {
	return a.Name == name && (a.OS == "" || a.OS == goos) && (a.Arch == "" || a.Arch == goarch)
}

// selectArtifact returns the first artifact of r for the platform that caps
// suffices for; found says whether r has one for the platform at all.
func selectArtifact(r *Release, name, goos, goarch string, caps map[string]bool) (a *Artifact, found bool) {
	has := func(need []string) bool {
		return !slices.ContainsFunc(need, func(c string) bool { return !caps[c] })
	}
	if !has(r.Requires) {
		for i := range r.Artifacts {
			found = found || r.Artifacts[i].matches(name, goos, goarch)
		}
		return nil, found
	}
	for i := range r.Artifacts {
		c := &r.Artifacts[i]
		if !c.matches(name, goos, goarch) {
			continue
		}
		found = true
		if has(c.needs()) {
			return c, true
		}
	}
	return nil, found
}

func (e *engine) usable(u, t *node) usableState {
	if t.rel == nil {
		return usableNo
	}
	a, found := selectArtifact(t.rel, e.q.Name, e.q.OS, e.q.Arch, u.caps)
	switch {
	case a != nil:
		return usableYes
	case found && !u.capsSet:
		return usableUnknown
	}
	return usableNo
}

type judged struct {
	st edgeState
	us usableState
}

// judge is the state of an edge and its usability, each worked out once.
func (e *engine) judge(u, t *node) (edgeState, usableState) {
	k := [2]*node{u, t}
	if j, ok := e.judged[k]; ok {
		return j.st, j.us
	}
	j := judged{us: e.usable(u, t), st: edgeClosed}
	if j.us != usableNo {
		j.st, _, _ = e.edge(u, t)
	}
	if e.judged == nil {
		e.judged = map[[2]*node]judged{}
	}
	e.judged[k] = j
	return j.st, j.us
}

func (e *engine) route() (*Route, error) {
	cur := e.nodes[e.cur]
	n := len(e.nodes)
	route := &Route{Current: cur.v.String(), Goal: cur.v.String(), Horizon: cur.v.String()}
	route.Latest = e.nodes[n-1].v.String()
	// Longest paths on a graph of strictly increasing versions, from the top.
	maybe, sure := make([]int, n), make([]int, n)
	for i := n - 1; i > e.cur; i-- {
		maybe[i], sure[i] = i, i
		// From the top, since an edge that cannot improve either value needs
		// no judging: most of them, as the values only rise.
		for j := n - 1; j > i; j-- {
			if maybe[j] <= maybe[i] && sure[j] <= sure[i] {
				continue
			}
			st, us := e.judge(e.nodes[i], e.nodes[j])
			if us == usableNo {
				continue
			}
			if st != edgeClosed {
				maybe[i] = max(maybe[i], maybe[j])
			}
			if st == edgeOpen && us == usableYes {
				sure[i] = max(sure[i], sure[j])
			}
		}
	}
	var hops []int
	for j := e.cur + 1; j < n; j++ {
		t := e.nodes[j]
		us := e.usable(cur, t)
		st, held, _ := e.edge(cur, t)
		if us == usableNo {
			route.Unusable = append(route.Unusable, e.unusable(t))
			continue
		}
		if st == edgeOpen {
			hops = append(hops, j)
			continue
		}
		route.addOffer(t, held)
	}
	goal, horizon := e.cur, e.cur
	for _, j := range hops {
		goal, horizon = max(goal, sure[j]), max(horizon, maybe[j])
	}
	route.Goal, route.Horizon = e.nodes[goal].v.String(), e.nodes[horizon].v.String()
	next := -1
	if e.q.Target != "" {
		tv, err := ParseVersion(e.q.Target)
		if err != nil {
			return nil, fmt.Errorf("selfupdate: target version %q: %w", e.q.Target, err)
		}
		next = e.routeTarget(route, tv, hops)
	} else {
		for _, j := range hops {
			// Hops ascend, so a tie on both values goes to the higher version.
			if next < 0 || maybe[j] > maybe[next] || (maybe[j] == maybe[next] && sure[j] >= sure[next]) {
				next = j
			}
		}
		if next < 0 {
			next = e.backward(route)
		}
	}
	e.finish(route, next, goal, maybe, sure)
	return route, nil
}

func (r *Route) addOffer(t *node, held []Reason) {
	offer := Offer{Version: t.v.String(), Reasons: held}
	for _, h := range held {
		if len(h.Unlock) == 0 {
			return
		}
		if !slices.Contains(offer.Needs, h.Unlock[0]) {
			offer.Needs = append(offer.Needs, h.Unlock[0])
		}
	}
	r.Offers = append(r.Offers, offer)
}

func (e *engine) unusable(t *node) Reason {
	rs := Reason{Code: reasonNoArtifact, Target: t.v.String(), Kind: ReasonCapability}
	_, found := selectArtifact(t.rel, e.q.Name, e.q.OS, e.q.Arch, e.nodes[e.cur].caps)
	if found {
		rs.Code = reasonMissingCapable
	}
	return rs
}

// routeTarget picks the step towards a specific version: any step from which
// it can be reached, certain ones first, then the highest.
func (e *engine) routeTarget(route *Route, tv Version, hops []int) int {
	cur := e.nodes[e.cur]
	target := slices.IndexFunc(e.nodes, func(n *node) bool { return n.rel != nil && n.v.Compare(tv) == 0 })
	route.Goal, route.Horizon = cur.v.String(), cur.v.String()
	if target < 0 {
		route.Blocked = append(route.Blocked, Reason{Code: reasonNoArtifact, Target: tv.String(), Kind: ReasonCapability})
		return -1
	}
	t := e.nodes[target]
	if target <= e.cur {
		st, held, _ := e.edge(cur, t)
		if e.usable(cur, t) != usableYes || st != edgeOpen {
			route.Blocked = append(route.Blocked, held...)
			return -1
		}
		if c := t.v.Compare(cur.v); c < 0 {
			route.Downgrade = true
		} else {
			route.Reinstall = true
		}
		route.Goal, route.Horizon = t.v.String(), t.v.String()
		return target
	}
	if e.usable(cur, t) != usableYes {
		route.Blocked = append(route.Blocked, e.unusable(t))
	}
	n := len(e.nodes)
	canMaybe, canSure := make([]bool, n), make([]bool, n)
	canMaybe[target], canSure[target] = true, true
	for i := target - 1; i > e.cur; i-- {
		for j := i + 1; j <= target && !canSure[i]; j++ {
			st, us := e.judge(e.nodes[i], e.nodes[j])
			if us == usableNo {
				continue
			}
			canMaybe[i] = canMaybe[i] || (st != edgeClosed && canMaybe[j])
			canSure[i] = canSure[i] || (st == edgeOpen && us == usableYes && canSure[j])
		}
	}
	next := -1
	for _, j := range hops {
		if j > target || !canMaybe[j] {
			continue
		}
		if next < 0 || !canSure[next] || canSure[j] {
			next = j
		}
	}
	if next < 0 {
		_, held, _ := e.edge(cur, t)
		route.Blocked = append(route.Blocked, held...)
		return -1
	}
	route.Horizon = t.v.String()
	if canSure[next] {
		route.Goal = t.v.String()
	}
	return next
}

// backward looks for a reinstallation, then a downgrade, only when no way
// leads forward: staying on the same version is the smaller step. It never enters the path search.
func (e *engine) backward(route *Route) int {
	cur := e.nodes[e.cur]
	down := -1
	for j := e.cur - 1; j >= 0; j-- {
		t := e.nodes[j]
		st, us := e.judge(cur, t)
		if st == edgeOpen && us == usableYes {
			if down < 0 {
				down = j
			}
			continue
		}
		if st != edgeOpen && us != usableNo {
			if _, held, _ := e.edge(cur, t); slices.ContainsFunc(held, func(r Reason) bool { return slices.Contains(r.Unlock, GrantDowngradeOffer) }) {
				route.addOffer(t, held)
			}
		}
	}
	if cur.rel != nil {
		if st, us := e.judge(cur, cur); st == edgeOpen && us == usableYes {
			route.Reinstall = true
			return e.cur
		}
	}
	route.Downgrade = down >= 0
	return down
}

func (e *engine) finish(route *Route, next, goal int, maybe, sure []int) {
	cur := e.nodes[e.cur]
	if next >= 0 {
		t := e.nodes[next]
		route.Next = t.rel
		route.Artifact, _ = selectArtifact(t.rel, e.q.Name, e.q.OS, e.q.Arch, cur.caps)
		_, _, route.Forced = e.edge(cur, t)
		route.Status = RouteAvailable
		route.Path = []Hop{{Version: t.v.String()}}
		for at := next; at > e.cur && e.q.Target == ""; {
			step, predicted := -1, false
			for j := at + 1; j < len(e.nodes); j++ {
				st, us := e.judge(e.nodes[at], e.nodes[j])
				if us == usableNo || st == edgeClosed || maybe[j] != maybe[at] {
					continue
				}
				if step < 0 || sure[j] >= sure[step] {
					step, predicted = j, st != edgeOpen || us != usableYes
				}
			}
			if step < 0 {
				break
			}
			route.Path = append(route.Path, Hop{Version: e.nodes[step].v.String(), Predicted: predicted})
			at = step
		}
	} else if e.nodes[len(e.nodes)-1].v.Compare(cur.v) > 0 || e.targetElsewhere(cur) {
		route.Status = RouteHeld
	}
	if e.q.Target == "" && goal < len(e.nodes)-1 && e.cur < len(e.nodes)-1 {
		g, latest := e.nodes[goal], e.nodes[len(e.nodes)-1]
		_, route.Blocked, _ = e.edge(g, latest)
		if e.usable(g, latest) == usableNo {
			route.Blocked = append(route.Blocked, e.unusable(latest))
		}
	}
	gv, err := ParseVersion(route.Goal)
	for _, cr := range e.notices {
		if !e.noticeHits(cr, cur) {
			continue
		}
		route.Notices = append(route.Notices, Notice{
			RuleID: cr.r.ID, Class: cr.r.Class, Message: cr.r.Message, URL: cr.r.URL, Attrs: cr.r.Attrs,
			Reachable: err == nil && cr.hasTo && cr.to.Contains(gv),
		})
	}
	sortReasons(route.Blocked)
	sortReasons(route.Unusable)
	slices.Sort(route.Forced)
	route.Forced = slices.Compact(route.Forced)
	slices.SortFunc(route.Notices, func(a, b Notice) int { return cmp.Compare(a.RuleID, b.RuleID) })
	for i := range route.Offers {
		sortReasons(route.Offers[i].Reasons)
		slices.Sort(route.Offers[i].Needs)
	}
	slices.SortFunc(route.Offers, func(a, b Offer) int {
		c, _ := CompareVersions(a.Version, b.Version)
		return c
	})
}

// targetElsewhere reports a target other than the running version.
func (e *engine) targetElsewhere(cur *node) bool {
	if e.q.Target == "" {
		return false
	}
	tv, err := ParseVersion(e.q.Target)
	return err == nil && tv.Compare(cur.v) != 0
}

// noticeHits decides a notice. One asking about the edge holds if it holds for
// a step to any newer release it names.
func (e *engine) noticeHits(cr *compiledRule, cur *node) bool {
	if !slices.ContainsFunc(cr.conds, func(c compiledCond) bool {
		return c.cond.Fact == "edge.crosses" || c.cond.Fact == "to.label"
	}) {
		return e.hit(cr, cur, nil, false) == hitYes
	}
	return slices.ContainsFunc(e.nodes[e.cur+1:], func(t *node) bool { return e.hit(cr, cur, t, false) == hitYes })
}

func sortReasons(rs []Reason) {
	slices.SortFunc(rs, func(a, b Reason) int {
		if c, err := CompareVersions(a.Target, b.Target); err == nil && c != 0 {
			return c
		}
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), strings.Compare(a.RuleID, b.RuleID), strings.Compare(a.Code, b.Code))
	})
}
