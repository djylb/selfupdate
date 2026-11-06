package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"
)

// Errors returned by [Updater].
var (
	ErrPendingRestart = errors.New("selfupdate: release is installed and awaits a restart")
	ErrWrongProduct   = errors.New("selfupdate: manifest is for another product")
	ErrRefused        = errors.New("selfupdate: update refused by policy")
	ErrNotChecked     = errors.New("selfupdate: candidate did not come from Check of this updater")
	ErrStaleManifest  = errors.New("selfupdate: manifest older than one seen before")
)

// File selects one file or directory of an artifact and where to install
// it.
type File struct {
	// Member names the file inside an archive artifact; see [Member].
	// With Dir it is the directory prefix to install, empty for the whole
	// archive.
	Member string
	// Target is the installed path. A relative path is relative to the
	// directory of the executable.
	Target string
	// Mode is used when Target does not exist yet; an existing target
	// keeps its own permissions. Zero means 0o644. Ignored with Dir.
	Mode fs.FileMode
	// Dir installs the tree under Member as the directory Target, replaced
	// as a whole (see [ExtractDir]). On Windows no file in the old tree may
	// be open while it is replaced.
	Dir bool
}

// Candidate is a release chosen by [Updater.Check]. Its exported fields
// describe it; changing them does not change what [Updater.Apply] installs.
type Candidate struct {
	// Published is the publication time of the manifest.
	Published time.Time
	from      *Updater
	sourceIdx int
	// Product, Version and Current identify the release and the version
	// being replaced.
	Product, Version, Current string
	// Notes is the release notes.
	Notes string
	// Channels and Labels come from the release.
	Channels, Labels []string
	// KeyIDs lists the trusted keys that signed the manifest.
	KeyIDs []string
	// Attrs comes from the release, for [Updater].FilesFor.
	Attrs []byte
	// Artifact is a copy of the artifact to install.
	Artifact Artifact
	artifact Artifact
	// Downgrade is set when Version is older than Current, and Reinstall when
	// it is the same.
	Downgrade, Reinstall bool
}

// Plan is the answer of [Updater.Check].
type Plan struct {
	// Route says where the installation can go and why.
	Route *Route
	// Candidate is what to install now, nil if nothing.
	Candidate *Candidate
	// Warnings lists problems that did not stop the check, such as a state
	// that cannot be written.
	Warnings []error
}

// ActionResult says how an [Action] ended.
type ActionResult int

const (
	// ActionDone means the action finished the update.
	ActionDone ActionResult = iota
	// ActionHandedOff means another process took over and its result is not
	// known yet. No update starts until [ConfirmHandoff] or
	// [Updater].HandoffTimeout, which counts as a failure.
	ActionHandedOff
)

// ActionContext is what an [ActionFunc] gets.
type ActionContext struct {
	// Candidate describes the release.
	Candidate *Candidate
	// Artifact is the verified artifact, for reading with [Extract] and the
	// like. It is only valid during the call: an installer must copy what it
	// keeps.
	Artifact io.ReaderAt
	// Params is the action's data from the manifest.
	Params []byte
	// StateSnapshot is the state, for [ImportState] in a new layout.
	StateSnapshot []byte
}

// ActionFunc installs an artifact in a way of the program's own, such as by
// running a verified installer. An error stops the update; one that wraps
// [ErrUpgradeFromRejected] is remembered. There is no journal behind an action:
// atomicity and rollback are up to it.
type ActionFunc func(ctx context.Context, a ActionContext) (ActionResult, error)

// Updater checks for, downloads, verifies and installs updates. The
// fields configure it; set them before first use and do not change them
// while a method runs. Methods may run concurrently: an update in flight
// holds the journal, so a second one fails with [ErrBusy].
//
// The typical program calls [Journal.Startup] on the updater's journal
// ([ExecutableJournal] unless Journal is set) first thing, passes the result to
// [Updater.RecordOutcome], commits after a health check when the status is
// pending, and from time to time calls [Updater.Update] and restarts.
type Updater struct {
	// Sources provide the signed manifest and the artifacts, tried in order.
	// A source behind the highest serial seen is passed over, and an artifact
	// missing from one source is fetched from the next. Required.
	Sources []Source
	// State remembers the serial, the rollout place and failures. Nil means
	// a [FileState] next to the journal.
	State State
	// OnManifest, when set, sees every manifest that passed verification,
	// before a release is chosen, and may stop the check by returning an
	// error. It runs on the calling goroutine with no lock held.
	OnManifest func(ctx context.Context, o *Opened) error
	// Authorize, when set, sees each candidate and may refuse it by
	// returning an error. It runs on the calling goroutine with no lock
	// held. Use it for dynamic decisions, such as waiting for a background
	// migration, or to allow only some signers.
	Authorize func(ctx context.Context, c *Candidate) error
	// Progress observes downloads; may be nil.
	Progress ProgressFunc
	// Now returns the current time for expiry checks; nil means
	// [time.Now].
	Now func() time.Time
	// FailureBackoff gives the wait after a failure in a row, starting at 1.
	// Nil means one hour, times four for each repeat, at most seven days.
	FailureBackoff func(failures int) time.Duration
	// FilesFor, when set, selects the files per candidate, for layouts that
	// change between releases, instead of Files. The paths stay in compiled
	// code; attrs and capabilities only choose among them.
	FilesFor func(c *Candidate) ([]File, error)
	// Actions registers ways to install artifacts besides replacing files.
	Actions map[string]ActionFunc
	// Facts holds the facts of this installation; see [Query].
	Facts map[string][]string
	// Trust is the signature policy. Its zero value rejects everything.
	Trust Trust
	// Journal records the updates. A zero Path means [ExecutableJournal]
	// (next to Executable, if set). Give an updater of data files its own
	// journal, such as [JournalFor] the data file, so that its updates do
	// not wait for the program's pending update. Call [Journal.Startup]
	// on this journal.
	Journal Journal
	// Product must equal the product named in the manifest. Required.
	Product string
	// Name is the artifact name to install; empty means Product.
	Name string
	// Current is the running version. Required: without it no release
	// can be judged newer.
	Current string
	// OS and Arch select the artifact; empty means the running system.
	OS, Arch string
	// Executable is the program file; empty means [os.Executable] with
	// symlinks resolved.
	Executable string
	// DownloadDir keeps downloads so that an interrupted one resumes on
	// the next attempt; updaters sharing it take turns per artifact. Empty
	// means a temporary directory per call, which is removed afterwards.
	DownloadDir string
	// Target asks for a specific version; see [Query].
	Target string
	// Grants lists what this run accepts; see [Query]. A background check
	// typically has none, a user asking for an update "user" and "rollout".
	Grants []string
	// Capabilities lists what the running program can do beyond
	// [LibraryCapabilities]; registered Actions count by themselves.
	Capabilities []string
	// LocalRules holds the program's own rules; see [Query].
	LocalRules []Rule
	// Files selects what to install. Empty means one file: the executable,
	// taken from the archive member named like the executable (with
	// ".exe" for windows), created with mode 0o755. Several entries may
	// install the same member at different targets.
	Files []File
	// Extract bounds and observes archive extraction.
	Extract ExtractOptions
	// MinSerial rejects manifests below it, compiled in to cover a lost state
	// and the first run.
	MinSerial uint64
	// MaxArtifactSize bounds the artifact size. Zero means 1 GiB.
	MaxArtifactSize int64
	// HandoffTimeout is how long a handed-off update may stay unconfirmed.
	// Zero means one hour.
	HandoffTimeout time.Duration
	// Verify, when set, runs after the artifact was downloaded, verified
	// and unpacked, and before anything is replaced; an error stops the
	// update and removes the staged files. An error wrapping
	// [ErrUpgradeFromRejected] (see [CheckUpgradeFrom]) is remembered, and
	// [Updater.Update] goes on with the next way. staged holds the unpacked
	// file or directory of each entry of Files, in order (the executable alone
	// when Files is empty; nothing for an action, which unpacks by itself).
	// artifact is the verified artifact, open for reading other members, for
	// example with [Extract]; its size and format are those of c.Artifact. Use
	// it to check that a new executable starts on this system before it
	// replaces the old one. It also runs with DryRun and runs on the calling
	// goroutine with no lock held.
	Verify func(ctx context.Context, c *Candidate, staged []string, artifact io.ReaderAt) error
	// DryRun makes Apply and Install stop after downloading, verifying and
	// staging: nothing is replaced and the staged files are removed.
	DryRun bool
	// InsecureNoState runs without a state: replays of older manifests are
	// not detected, failures are forgotten and rollouts stay closed.
	InsecureNoState bool
	// InsecureAcceptStale accepts manifests older than one seen before, for
	// recovering by hand.
	InsecureAcceptStale bool
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) platform() (string, string) {
	goos, goarch := u.OS, u.Arch
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return goos, goarch
}

func (u *Updater) name() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Product
}

// journal resolves the journal the updater records in.
func (u *Updater) journal() (Journal, error) {
	j := u.Journal
	if j.Path != "" {
		return j, nil
	}
	exe, err := executable(u.Executable)
	if err != nil {
		return Journal{}, err
	}
	j.Path = JournalFor(exe).Path
	return j, nil
}

func (u *Updater) state() (State, error) {
	if u.InsecureNoState {
		return nil, nil
	}
	if u.State != nil {
		return u.State, nil
	}
	j, err := u.journal()
	if err != nil {
		return nil, err
	}
	return FileState(defaultStatePath(j)), nil
}

// fetched is a manifest accepted from a source.
type fetched struct {
	opened *Opened
	data   StateData
	source int
}

// fetch takes the manifest from the first source that gives an acceptable one.
func (u *Updater) fetch(ctx context.Context, plan *Plan) (*fetched, error) {
	var errs []error
	for i, src := range u.Sources {
		f, err := u.fetchFrom(ctx, src, plan)
		if err == nil {
			f.source = i
			return f, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (u *Updater) fetchFrom(ctx context.Context, src Source, plan *Plan) (*fetched, error) {
	raw, err := src.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	opened, err := OpenManifest(raw, u.Trust, u.now())
	if err != nil {
		return nil, err
	}
	m := opened.Manifest
	if m.Product != u.Product {
		return nil, fmt.Errorf("%w: %q", ErrWrongProduct, m.Product)
	}
	caps := toSet(u.capabilities(), LibraryCapabilities())
	for _, c := range m.Requires {
		if !caps[c] {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedManifest, c)
		}
	}
	if m.Serial < u.MinSerial && !u.InsecureAcceptStale {
		return nil, fmt.Errorf("%w: serial %d, below %d", ErrStaleManifest, m.Serial, u.MinSerial)
	}
	f := &fetched{opened: opened}
	st, err := u.state()
	if err != nil {
		return nil, err
	}
	if st == nil {
		return f, nil
	}
	// A manifest that was not signed is no evidence of anything: never let it
	// move what later manifests are compared with.
	if len(opened.KeyIDs) > 0 && !u.InsecureAcceptStale {
		err := st.Update(ctx, func(d *StateData) error {
			if err := d.Advance(m.Serial, opened.Hash); err != nil {
				return err
			}
			d.ensureInstallID()
			u.prune(d, m)
			f.data = *d
			return nil
		})
		if err == nil || errors.Is(err, ErrStaleManifest) || ctx.Err() != nil {
			return f, err
		}
		plan.Warnings = append(plan.Warnings, fmt.Errorf("selfupdate: state not saved: %w", err))
	}
	d, err := st.Load(ctx)
	if err != nil {
		plan.Warnings = append(plan.Warnings, fmt.Errorf("selfupdate: state not read: %w", err))
		return f, nil
	}
	if len(opened.KeyIDs) > 0 && !u.InsecureAcceptStale {
		probe := d
		if err := probe.Advance(m.Serial, opened.Hash); err != nil {
			return nil, err
		}
	}
	f.data = d
	return f, nil
}

// prune drops records that lost their meaning: failures of artifacts the
// manifest no longer lists, and downgrades it no longer offers. A failure of
// another source version stays: that version may be running again after a
// rollback, and matching compares the source anyway.
func (u *Updater) prune(d *StateData, m *Manifest) {
	digests := map[string]bool{}
	for i := range m.Releases {
		for j := range m.Releases[i].Artifacts {
			digests[m.Releases[i].Artifacts[j].Digest()] = true
		}
	}
	d.Failed = slices.DeleteFunc(d.Failed, func(f FailedEdge) bool { return !digests[f.Digest] })
	d.Downgraded = slices.DeleteFunc(d.Downgraded, func(x string) bool { return !offersDowngradeFrom(m, x) })
}

func offersDowngradeFrom(m *Manifest, version string) bool {
	v, err := ParseVersion(version)
	if err != nil {
		return false
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		if r.Effect != EffectAllow {
			continue
		}
		from, _ := parseOrAll(r.From)
		to, _ := parseOrAll(r.To)
		if from.Contains(v) && slices.ContainsFunc(m.Releases, func(t Release) bool {
			tv, err := ParseVersion(t.Version)
			return err == nil && tv.Compare(v) < 0 && to.Contains(tv)
		}) {
			return true
		}
	}
	return false
}

func (u *Updater) capabilities() []string {
	out := slices.Clone(u.Capabilities)
	for kind := range u.Actions {
		out = append(out, "action:"+kind)
	}
	return out
}

// memoryRules turns what the state remembers into local rules, so that Resolve
// has one way to close an edge and no clock.
func (u *Updater) memoryRules(m *Manifest, d *StateData, q *Query) []Rule {
	var out []Rule
	caps := toSet(q.Capabilities, LibraryCapabilities())
	now := u.now()
	for i := range m.Releases {
		r := &m.Releases[i]
		a, _ := selectArtifact(r, q.Name, q.OS, q.Arch, caps)
		if a == nil {
			continue
		}
		digest := a.Digest()
		held := slices.ContainsFunc(d.Failed, func(f FailedEdge) bool {
			if !sameVersion(f.From, q.Current) || f.Digest != digest {
				return false
			}
			return f.Rejected || (sameVersion(f.To, r.Version) && now.Before(f.At.Add(u.backoff(f.Failures))))
		})
		if held {
			out = append(out, Rule{
				ID: "failed:" + r.Version, Effect: EffectBlock, From: "=" + q.Current, To: "=" + r.Version, Reason: reasonFailed,
				Unlock: []string{GrantRetryFailed}, kind: ReasonFailed,
			})
		}
	}
	for _, x := range d.Downgraded {
		if offersDowngradeFrom(m, x) {
			out = append(out, Rule{ID: "downgraded:" + x, Effect: EffectBlock, To: "=" + x, Reason: "downgraded", kind: ReasonDowngrade})
		}
	}
	return out
}

// Check fetches and verifies the manifest and works out where to go. That an
// installation is up to date or held back is no error: it is in
// [Plan].Route, and Plan.Candidate is nil. An error means no trustworthy answer
// was found, or [ErrPendingRestart] when the release is installed already and
// awaits a restart.
func (u *Updater) Check(ctx context.Context) (*Plan, error) {
	if len(u.Sources) == 0 || u.Product == "" {
		return nil, errors.New("selfupdate: Updater needs Sources and Product")
	}
	if _, err := ParseVersion(u.Current); err != nil {
		return nil, fmt.Errorf("selfupdate: current version %q: %w", u.Current, err)
	}
	plan := &Plan{}
	f, err := u.fetch(ctx, plan)
	if err != nil {
		return nil, err
	}
	opened := f.opened
	m := opened.Manifest
	if u.OnManifest != nil {
		if err := u.OnManifest(ctx, opened); err != nil {
			return nil, err
		}
	}
	pending, err := u.settle(ctx, &f.data, plan)
	if err != nil {
		return nil, err
	}
	goos, goarch := u.platform()
	q := Query{
		Current: u.Current, Name: u.name(), OS: goos, Arch: goarch, Target: u.Target, InstallID: f.data.InstallID,
		Facts: u.Facts, Grants: u.Grants, Capabilities: u.capabilities(),
	}
	q.LocalRules = append(slices.Clone(u.LocalRules), u.memoryRules(m, &f.data, &q)...)
	route, err := Resolve(m, q)
	if err != nil {
		return nil, err
	}
	plan.Route = route
	if pending {
		route.Status, route.Next, route.Artifact = RouteHandoffPending, nil, nil
		return plan, nil
	}
	if route.Next == nil {
		return plan, nil
	}
	maxSize := u.MaxArtifactSize
	if maxSize <= 0 {
		maxSize = 1 << 30
	}
	if route.Artifact.Size > maxSize {
		return nil, fmt.Errorf("%w: artifact of %d bytes", ErrTooLarge, route.Artifact.Size)
	}
	if a := f.data.Attempt; a != nil && a.Done && sameVersion(a.To, route.Next.Version) {
		return nil, fmt.Errorf("%w: %s", ErrPendingRestart, a.To)
	}
	if j, err := u.journal(); err == nil {
		if out, err := j.Peek(); err == nil && out.Status == StatusPending && sameVersion(out.Version, route.Next.Version) {
			return nil, fmt.Errorf("%w: %s", ErrPendingRestart, out.Version)
		}
	}
	c := &Candidate{
		Published: m.Published,
		from:      u,
		sourceIdx: f.source,
		Product:   m.Product,
		Version:   route.Next.Version,
		Channels:  route.Next.Channels,
		Labels:    route.Next.Labels,
		Current:   u.Current,
		Notes:     route.Next.Notes,
		KeyIDs:    opened.KeyIDs,
		Attrs:     route.Next.Attrs,
		Artifact:  route.Artifact.clone(),
		artifact:  route.Artifact.clone(),
		Downgrade: route.Downgrade,
		Reinstall: route.Reinstall,
	}
	if u.Authorize != nil {
		if err := u.Authorize(ctx, c); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}
	plan.Candidate = c
	return plan, nil
}

// settle turns what earlier runs left unfinished into failures before routing,
// and reports a handed-off update still in its window. d is brought up to date.
// A state that cannot be written gives a warning, and the result holds for this
// check only.
func (u *Updater) settle(ctx context.Context, d *StateData, plan *Plan) (pending bool, err error) {
	timeout := u.HandoffTimeout
	if timeout <= 0 {
		timeout = time.Hour
	}
	now := u.now()
	expired := func(h *Handoff) bool { return h != nil && now.Sub(h.At) >= timeout }
	due := func(a *Handoff) bool {
		if a == nil {
			return false
		}
		settled, _ := u.settleAttempt(a, expired(a))
		return settled
	}
	st, err := u.state()
	if err != nil {
		return false, err
	}
	if st != nil && (expired(d.Handoff) || due(d.Attempt)) {
		apply := func(s *StateData) {
			if h := s.Handoff; expired(h) {
				s.Handoff = nil
				u.recordFailure(s, h.From, h.To, h.Digest, now)
			}
			if a := s.Attempt; a != nil {
				if settled, failed := u.settleAttempt(a, expired(a)); settled {
					s.Attempt = nil
					if failed {
						u.recordFailure(s, a.From, a.To, a.Digest, now)
					}
				}
			}
		}
		err = st.Update(ctx, func(s *StateData) error {
			apply(s)
			*d = *s
			return nil
		})
		if err != nil {
			if ctx.Err() != nil {
				return false, err
			}
			plan.Warnings = append(plan.Warnings, fmt.Errorf("selfupdate: state not saved: %w", err))
			apply(d)
		}
	}
	return d.Handoff != nil && !expired(d.Handoff), nil
}

// settleAttempt says whether the record of an attempt has served its purpose,
// and whether it ends in a failure.
func (u *Updater) settleAttempt(a *Handoff, expired bool) (settled, failed bool) {
	if a.Done {
		// The installer finished. The record lasts until the new version runs;
		// a source version still running after the timeout means it did not
		// take effect.
		if !sameVersion(u.Current, a.From) {
			return true, false
		}
		return expired, expired
	}
	if !u.attemptLost() {
		return false, false
	}
	switch {
	case sameVersion(a.From, a.To):
		return true, false // A reinstallation has no other version to fall back to.
	case sameVersion(u.Current, a.To):
		// Confirmed, or undone and awaiting the restart: only the source
		// version can tell. The next attempt overwrites the record.
		return false, false
	case sameVersion(u.Current, a.From):
		return true, true
	}
	return true, false
}

// attemptLost reports an update whose fate no longer depends on anybody: no
// swap is under way or awaiting confirmation.
func (u *Updater) attemptLost() bool {
	j, err := u.journal()
	if err != nil {
		return false
	}
	out, err := j.Peek()
	return err == nil && (out.Status == StatusIdle || out.Status == StatusCleanup)
}

func (u *Updater) backoff(failures int) time.Duration {
	if u.FailureBackoff != nil {
		return u.FailureBackoff(failures)
	}
	const limit = 7 * 24 * time.Hour
	wait := time.Hour
	for i := 1; i < failures && wait < limit; i++ {
		wait *= 4
	}
	return min(wait, limit)
}

// recordFailure counts a failure that may be transient, with a wait that grows.
func (u *Updater) recordFailure(d *StateData, from, to, digest string, now time.Time) {
	n := 1
	for i := range d.Failed {
		f := &d.Failed[i]
		if !f.Rejected && f.From == from && f.To == to {
			if f.Digest == digest {
				n = f.Failures + 1
			}
			d.Failed = slices.Delete(d.Failed, i, i+1)
			break
		}
	}
	d.Failed = append(d.Failed, FailedEdge{From: from, To: to, Digest: digest, Failures: n, At: now})
}

func recordRejected(d *StateData, from, to, digest string) {
	if !slices.ContainsFunc(d.Failed, func(f FailedEdge) bool { return f.Rejected && f.From == from && f.Digest == digest }) {
		d.Failed = append(d.Failed, FailedEdge{From: from, To: to, Digest: digest, Rejected: true})
	}
}

// RecordOutcome remembers a failed update reported by [Journal.Startup], so
// that the next checks wait before trying that edge again and take another way
// meanwhile. Only a new version that never confirmed itself counts: an
// interrupted swap says nothing about it. Call it after every Startup; it does
// nothing otherwise. Should it never run, or after [Journal.Rollback], the next
// [Updater.Check] counts the undone update as a failure by itself.
func (u *Updater) RecordOutcome(ctx context.Context, out Outcome) error {
	if out.Status != StatusRolledBack {
		return nil
	}
	st, err := u.state()
	if err != nil || st == nil {
		return err
	}
	now := u.now()
	return st.Update(ctx, func(d *StateData) error {
		d.Attempt = nil
		if out.Cause == RollbackUnconfirmed && out.Digest != "" {
			u.recordFailure(d, out.Previous, out.Version, out.Digest, now)
		}
		return nil
	})
}

// RejectUpgrade is for a new version that finds on its first start that it
// cannot take over from out.Previous (see [CheckUpgradeFrom]): it remembers
// that and rolls the update back. Restart afterwards.
func (u *Updater) RejectUpgrade(ctx context.Context, out Outcome) error {
	st, err := u.state()
	if err != nil {
		return err
	}
	if st != nil {
		err = st.Update(ctx, func(d *StateData) error {
			d.Attempt = nil
			recordRejected(d, out.Previous, out.Version, out.Digest)
			return nil
		})
	}
	j, jerr := u.journal()
	if jerr != nil {
		return errors.Join(err, jerr)
	}
	return errors.Join(err, j.Rollback(ctx))
}

func sameVersion(a, b string) bool {
	c, err := CompareVersions(a, b)
	return err == nil && c == 0
}

// Update runs [Updater.Check] and [Updater.Apply] and returns the plan it
// followed; check Plan.Candidate for whether something was installed. A new
// version refusing the running one does not end it: Update goes on with the
// next way. It never downgrades: a downgrade stays in the plan for the caller
// to apply.
func (u *Updater) Update(ctx context.Context) (*Plan, error) {
	tried := map[string]bool{}
	for {
		plan, err := u.Check(ctx)
		if err != nil {
			return nil, err
		}
		c := plan.Candidate
		if c == nil || c.Downgrade {
			return plan, nil
		}
		tried[c.Version] = true
		err = u.Apply(ctx, c)
		if errors.Is(err, ErrUpgradeFromRejected) {
			again, cerr := u.Check(ctx)
			if cerr == nil && again.Candidate != nil && !tried[again.Candidate.Version] {
				continue
			}
		}
		if err != nil {
			return plan, err
		}
		return plan, nil
	}
}

// Apply installs c as a pending update: the replaced files are kept as
// backups until [Journal.Commit] confirms the new version, and the next
// [Journal.Startup] rolls back an update that was never confirmed. Restart
// the program afterwards to run the new version. c must come from Check
// of this updater.
//
// Apply checks the journal before downloading anything: while another
// update is pending or in progress, or a finished one left files that
// cannot be deleted yet, it fails with [ErrBusy] at once.
func (u *Updater) Apply(ctx context.Context, c *Candidate) error {
	return u.install(ctx, c, true)
}

// Install installs c at once, with no confirmation step. It suits data
// files, such as rule databases, and programs that do not check their own
// health. The replaced files are deleted when the swap succeeds.
func (u *Updater) Install(ctx context.Context, c *Candidate) error {
	return u.install(ctx, c, false)
}

func executable(p string) (string, error) {
	if p == "" {
		var err error
		if p, err = os.Executable(); err != nil {
			return "", err
		}
	}
	p, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

func (u *Updater) files(c *Candidate) ([]File, error) {
	selected := u.Files
	if u.FilesFor != nil {
		var err error
		if selected, err = u.FilesFor(c); err != nil {
			return nil, err
		}
	}
	exe, err := executable(u.Executable)
	if err != nil && (len(selected) == 0 || !allAbs(selected)) {
		return nil, err
	}
	if len(selected) == 0 {
		goos, _ := u.platform()
		member := u.name()
		if goos == "windows" {
			member += ".exe"
		}
		return []File{{Member: member, Target: exe, Mode: 0o755}}, nil
	}
	out := make([]File, len(selected))
	for i, f := range selected {
		if !filepath.IsAbs(f.Target) {
			f.Target = filepath.Join(filepath.Dir(exe), f.Target)
		}
		out[i] = f
	}
	return out, nil
}

func allAbs(files []File) bool {
	for _, f := range files {
		if !filepath.IsAbs(f.Target) {
			return false
		}
	}
	return true
}

func (u *Updater) install(ctx context.Context, c *Candidate, pending bool) (err error) {
	if c == nil || c.from != u {
		return ErrNotChecked
	}
	kind := actionReplace
	if a := c.artifact.Action; a != nil && a.Kind != "" {
		kind = a.Kind
	}
	st, err := u.state()
	if err != nil {
		return err
	}
	// Without a place to remember the outcome, a failure would repeat forever.
	if st != nil && !u.DryRun {
		if err := st.Update(ctx, func(*StateData) error { return nil }); err != nil {
			return fmt.Errorf("selfupdate: state cannot be written: %w", err)
		}
	}
	defer func() {
		if st != nil && errors.Is(err, ErrUpgradeFromRejected) {
			err = errors.Join(err, st.Update(context.WithoutCancel(ctx), func(d *StateData) error {
				recordRejected(d, c.Current, c.Version, c.artifact.Digest())
				return nil
			}))
		}
	}()
	var files []File
	if kind == actionReplace {
		if files, err = u.files(c); err != nil {
			return err
		}
	}
	j, err := u.journal()
	if err != nil {
		return err
	}
	out, err := j.Peek()
	if err == nil && out.Status == StatusCleanup {
		// Leftovers of a finished update; delete them now if possible.
		if _, err = j.Recover(ctx); err == nil {
			out, err = j.Peek()
		}
	}
	switch {
	case err != nil:
		return err
	case out.Status == StatusPending && sameVersion(out.Version, c.Version):
		return fmt.Errorf("%w: %s", ErrPendingRestart, out.Version)
	case out.Status != StatusIdle:
		return ErrBusy
	}
	for _, f := range files {
		if err := CheckWritable(filepath.Dir(f.Target)); err != nil {
			return err
		}
	}
	a := c.artifact
	if kind == actionReplace && !a.Format.archive() && (len(files) != 1 || files[0].Dir) {
		return fmt.Errorf("selfupdate: a %v artifact installs exactly one file", a.Format)
	}
	dir := u.DownloadDir
	if dir == "" {
		if dir, err = os.MkdirTemp("", "selfupdate-"); err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
	}
	download := filepath.Join(dir, "selfupdate-"+downloadKey(a)+".download")
	f, err := u.downloadShared(ctx, c, a, download)
	if err != nil {
		return err
	}
	defer func() {
		closeQuietly(f)
		_ = os.Remove(download)
	}()
	if kind != actionReplace {
		return u.runAction(ctx, c, kind, st, f)
	}
	targets := make([]string, len(files))
	for i, f := range files {
		targets[i] = f.Target
	}
	staged, err := j.Stage(ctx, targets...)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, staged.Abort(context.WithoutCancel(ctx))) }()
	// A member installed at several targets is extracted once and copied.
	var members []Member
	first := map[string]string{} // member name -> staged path
	var copies [][2]string       // from, to
	for i, p := range staged.Paths() {
		fl := files[i]
		if fl.Dir {
			continue
		}
		if from, ok := first[fl.Member]; ok {
			copies = append(copies, [2]string{from, p})
			continue
		}
		first[fl.Member] = p
		members = append(members, Member{Name: fl.Member, Path: p, Mode: fl.Mode})
	}
	if len(members) > 0 {
		if err := Extract(ctx, f, a.Size, a.Format, members, u.Extract); err != nil {
			return err
		}
	}
	for _, c := range copies {
		if err := copyStaged(c[0], c[1]); err != nil {
			return err
		}
	}
	for i, p := range staged.Paths() {
		if fl := files[i]; fl.Dir {
			if err := ExtractDir(ctx, f, a.Size, a.Format, fl.Member, p, u.Extract); err != nil {
				return err
			}
		}
	}
	if u.Verify != nil {
		if err := u.Verify(ctx, c, staged.Paths(), f); err != nil {
			return err
		}
	}
	if u.DryRun {
		return nil
	}
	opts := ReplaceOptions{Version: c.Version, Previous: c.Current, Digest: a.Digest(), Pending: pending}
	if st != nil {
		at := &Handoff{At: u.now(), From: c.Current, To: c.Version, Digest: opts.Digest}
		if err := st.Update(ctx, func(d *StateData) error {
			if d.Handoff != nil || (d.Attempt != nil && d.Attempt.Done) {
				return ErrBusy // An installer owns the installation.
			}
			if pending {
				// Written first: a rollback may leave no other trace in the state.
				d.Attempt = at
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if err := staged.Replace(ctx, opts); err != nil {
		if st != nil {
			err = errors.Join(err, st.Update(context.WithoutCancel(ctx), func(d *StateData) error {
				d.Attempt = nil
				return nil
			}))
		}
		return err
	}
	return u.recordDowngrade(ctx, c, st)
}

// downloadShared is download for updaters that may share DownloadDir: they take
// turns while the file is written. A finished file is only read, so the lock
// ends with the download, and whoever comes next verifies and reuses the file.
func (u *Updater) downloadShared(ctx context.Context, c *Candidate, a Artifact, dst string) (*os.File, error) {
	if u.DownloadDir != "" {
		l, err := lockFile(ctx, dst+".lock")
		if err != nil {
			return nil, err
		}
		defer l.unlock()
	}
	return u.download(ctx, c, a, dst)
}

// download fetches the artifact from the source of the manifest, or else from
// the others, which may be ahead: the content is checked either way.
func (u *Updater) download(ctx context.Context, c *Candidate, a Artifact, dst string) (*os.File, error) {
	f, err := Download(ctx, u.Sources[c.sourceIdx], a, dst, u.Progress)
	if err == nil {
		return f, nil
	}
	errs := []error{err}
	for i, src := range u.Sources {
		if i == c.sourceIdx {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		f, err := Download(ctx, src, a, dst, u.Progress)
		if err == nil {
			return f, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// recordDowngrade keeps a downgrade from being undone by the next check while
// the manifest still offers it.
func (u *Updater) recordDowngrade(ctx context.Context, c *Candidate, st State) error {
	if !c.Downgrade || st == nil {
		return nil
	}
	return st.Update(context.WithoutCancel(ctx), func(d *StateData) error {
		if !slices.Contains(d.Downgraded, c.Current) {
			d.Downgraded = append(d.Downgraded, c.Current)
		}
		return nil
	})
}

func (u *Updater) runAction(ctx context.Context, c *Candidate, kind string, st State, f *os.File) error {
	action, ok := u.Actions[kind]
	if !ok {
		return fmt.Errorf("selfupdate: no action %q", kind)
	}
	if u.Verify != nil {
		if err := u.Verify(ctx, c, nil, f); err != nil {
			return err
		}
	}
	if u.DryRun {
		return nil
	}
	// One installer at a time, also against a swap of the journal's own. The
	// action runs under this file lock: it may use the state and the journal,
	// but must not stage files or apply another candidate of this journal.
	j, err := u.journal()
	if err != nil {
		return err
	}
	l, err := tryLockFile(j.stageLock())
	if errors.Is(err, errLocked) {
		return ErrBusy
	}
	if err != nil {
		return err
	}
	defer l.unlock()
	// The journal was checked before the download: a swap may have come since.
	out, err := j.Peek()
	if err != nil {
		return err
	}
	if out.Status != StatusIdle {
		return ErrBusy
	}
	ac := ActionContext{Candidate: c, Artifact: f, Params: c.artifact.Action.Params}
	if st != nil {
		// Recorded before the installer starts: it may end this process, and a
		// restart must not start a second one.
		h := &Handoff{At: u.now(), From: c.Current, To: c.Version, Digest: c.artifact.Digest()}
		var snapshot StateData
		if err := st.Update(ctx, func(d *StateData) error {
			if d.Handoff != nil {
				return ErrBusy
			}
			if a := d.Attempt; a != nil && a.Done {
				// A candidate from before that installer finished.
				if sameVersion(a.To, c.Version) && a.Digest == h.Digest {
					return fmt.Errorf("%w: %s", ErrPendingRestart, a.To)
				}
				return ErrBusy
			}
			snapshot = *d
			d.Handoff = h
			return nil
		}); err != nil {
			return err
		}
		if ac.StateSnapshot, err = json.Marshal(&snapshot); err != nil {
			return errors.Join(err, clearHandoff(ctx, st))
		}
	}
	res, err := action(ctx, ac)
	if err != nil {
		if st != nil {
			err = errors.Join(err, clearHandoff(ctx, st))
		}
		return err
	}
	if res != ActionHandedOff && st != nil {
		now := u.now()
		if err := st.Update(context.WithoutCancel(ctx), func(d *StateData) error {
			d.Handoff = nil
			// Remembered until the new version runs, so that no other process
			// starts the installer again. A reinstallation changes no version.
			if !sameVersion(c.Current, c.Version) {
				d.Attempt = &Handoff{At: now, From: c.Current, To: c.Version, Digest: c.artifact.Digest(), Done: true}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return u.recordDowngrade(ctx, c, st)
}

func clearHandoff(ctx context.Context, st State) error {
	return st.Update(context.WithoutCancel(ctx), func(d *StateData) error {
		d.Handoff = nil
		return nil
	})
}

// copyStaged copies the staged file from to the staging path to, with the
// same permission bits. Like extraction it never replaces an existing file.
func copyStaged(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer closeQuietly(in)
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	return writeLimited(to, fi.Mode().Perm(), in, fi.Size())
}

// downloadKey names the download file after the content, so a resumed
// download never mixes two artifacts.
func downloadKey(a Artifact) string {
	if a.SHA512 != "" {
		return a.SHA512[:32]
	}
	return a.SHA256[:32]
}
