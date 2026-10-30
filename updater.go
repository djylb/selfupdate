package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"
)

// Errors returned by [Updater].
var (
	ErrUpToDate       = errors.New("selfupdate: no newer release")
	ErrNoArtifact     = errors.New("selfupdate: newer release has no artifact for this name and platform")
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
	// Product, Version and Channel identify the release.
	Product, Version, Channel string
	// Current is the version being replaced.
	Current string
	// Notes is the release notes.
	Notes string
	// KeyIDs lists the trusted keys that signed the manifest.
	KeyIDs []string
	// Artifact is a copy of the artifact to install.
	Artifact Artifact
	artifact Artifact
	// Downgrade is set when Version is older than Current, which
	// [Updater.AllowDowngrade] must permit.
	Downgrade bool
}

// Updater checks for, downloads, verifies and installs updates. The
// fields configure it; set them before first use and do not change them
// while a method runs. Methods may run concurrently: an update in flight
// holds the journal, so a second one fails with [ErrBusy].
//
// The typical program calls [Journal.Startup] on the updater's journal
// ([ExecutableJournal] unless Journal is set) first thing, commits after a
// health check when the status is pending, and from time to time calls
// [Updater.Update] and restarts.
type Updater struct {
	// Source provides the signed manifest and the artifacts. Required.
	Source Source
	// OnManifest, when set, sees every manifest that passed verification,
	// before a release is chosen, and may stop the check by returning an
	// error. Use it to record [Manifest.Published] for MinPublished even
	// when nothing new is offered. It runs on the calling goroutine with
	// no lock held.
	OnManifest func(ctx context.Context, o *Opened) error
	// Authorize, when set, sees each candidate and may refuse it by
	// returning an error. It runs on the calling goroutine with no lock
	// held. Use it when a remote party must not be able to force updates,
	// for example to ask a user or to allow only some signers.
	Authorize func(ctx context.Context, c *Candidate) error
	// Skip, when set, hides the releases for which it returns true, such
	// as a version that was rolled back before ([Outcome.Version] with
	// [StatusRolledBack]); store those and skip them, so a broken release
	// is not installed again and again.
	Skip func(version string) bool
	// Progress observes downloads; may be nil.
	Progress ProgressFunc
	// Now returns the current time for expiry checks; nil means
	// [time.Now].
	Now func() time.Time
	// MinPublished, when set, rejects manifests published before it. Store
	// [Manifest.Published] of each manifest seen (see OnManifest) and pass
	// it here, so that an attacker cannot serve an older, still unexpired
	// manifest to hide a newer release (a freeze attack).
	MinPublished time.Time
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
	// Channels lists the release channels accepted besides the default
	// channel.
	Channels []string
	// Files selects what to install. Empty means one file: the executable,
	// taken from the archive member named like the executable (with
	// ".exe" for windows), created with mode 0o755.
	Files []File
	// Extract bounds and observes archive extraction.
	Extract ExtractOptions
	// MaxArtifactSize bounds the artifact size. Zero means 1 GiB.
	MaxArtifactSize int64
	// AllowPrerelease accepts pre-release versions.
	AllowPrerelease bool
	// AllowDowngrade accepts a release older than Current when it is the
	// newest one offered. Without it older releases are never installed,
	// so replaying an old signed manifest cannot roll clients back.
	AllowDowngrade bool
	// DryRun makes Apply and Install stop after downloading, verifying and
	// staging: nothing is replaced and the staged files are removed.
	DryRun bool
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

func (u *Updater) channelOK(ch string) bool {
	if ch == "" {
		return true
	}
	return slices.Contains(u.Channels, ch)
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

// Check fetches and verifies the manifest and returns the release to
// install. It returns [ErrUpToDate] when no release is newer,
// [ErrNoArtifact] when newer releases exist but none has an artifact for
// the name and platform (a configuration error worth reporting), and
// [ErrPendingRestart] when the release is installed already and awaits a
// restart.
func (u *Updater) Check(ctx context.Context) (*Candidate, error) {
	if u.Source == nil || u.Product == "" {
		return nil, errors.New("selfupdate: Updater needs Source and Product")
	}
	current, err := ParseVersion(u.Current)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: current version %q: %w", u.Current, err)
	}
	data, err := u.Source.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	opened, err := OpenManifest(data, u.Trust, u.now())
	if err != nil {
		return nil, err
	}
	m := opened.Manifest
	if m.Product != u.Product {
		return nil, fmt.Errorf("%w: %q", ErrWrongProduct, m.Product)
	}
	if !u.MinPublished.IsZero() && m.Published.Before(u.MinPublished) {
		return nil, fmt.Errorf("%w: published %s, before %s", ErrStaleManifest,
			m.Published.Format(time.RFC3339), u.MinPublished.Format(time.RFC3339))
	}
	if u.OnManifest != nil {
		if err := u.OnManifest(ctx, opened); err != nil {
			return nil, err
		}
	}
	goos, goarch := u.platform()
	var best *Release
	var bestV Version
	var bestA Artifact
	missing := false
	for i := range m.Releases {
		r := &m.Releases[i]
		v, _ := ParseVersion(r.Version) // validated by OpenManifest
		if !u.channelOK(r.Channel) || (v.IsPrerelease() && !u.AllowPrerelease) || (u.Skip != nil && u.Skip(r.Version)) {
			continue
		}
		a, ok := r.Artifact(u.name(), goos, goarch)
		if !ok {
			missing = missing || v.Compare(current) > 0
			continue
		}
		if best == nil || v.Compare(bestV) > 0 {
			best, bestV, bestA = r, v, a
		}
	}
	order := 0
	if best != nil {
		order = bestV.Compare(current)
	}
	if best == nil || order == 0 || (order < 0 && !u.AllowDowngrade) {
		if missing {
			return nil, ErrNoArtifact
		}
		return nil, ErrUpToDate
	}
	maxSize := u.MaxArtifactSize
	if maxSize <= 0 {
		maxSize = 1 << 30
	}
	if bestA.Size > maxSize {
		return nil, fmt.Errorf("%w: artifact of %d bytes", ErrTooLarge, bestA.Size)
	}
	if j, err := u.journal(); err == nil {
		if out, err := j.Peek(); err == nil && out.Status == StatusPending && sameVersion(out.Version, best.Version) {
			return nil, fmt.Errorf("%w: %s", ErrPendingRestart, out.Version)
		}
	}
	c := &Candidate{
		Published: m.Published,
		from:      u,
		Product:   m.Product,
		Version:   best.Version,
		Channel:   best.Channel,
		Current:   u.Current,
		Notes:     best.Notes,
		KeyIDs:    opened.KeyIDs,
		Artifact:  bestA,
		artifact:  bestA,
		Downgrade: order < 0,
	}
	if u.Authorize != nil {
		if err := u.Authorize(ctx, c); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}
	return c, nil
}

func sameVersion(a, b string) bool {
	c, err := CompareVersions(a, b)
	return err == nil && c == 0
}

// Update runs [Updater.Check] and [Updater.Apply]. It returns the
// installed candidate, or the error of either step.
func (u *Updater) Update(ctx context.Context) (*Candidate, error) {
	c, err := u.Check(ctx)
	if err != nil {
		return nil, err
	}
	return c, u.Apply(ctx, c)
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

func (u *Updater) files() ([]File, error) {
	exe, err := executable(u.Executable)
	if err != nil && (len(u.Files) == 0 || !allAbs(u.Files)) {
		return nil, err
	}
	if len(u.Files) == 0 {
		goos, _ := u.platform()
		member := u.name()
		if goos == "windows" {
			member += ".exe"
		}
		return []File{{Member: member, Target: exe, Mode: 0o755}}, nil
	}
	out := make([]File, len(u.Files))
	for i, f := range u.Files {
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
	files, err := u.files()
	if err != nil {
		return err
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
	if !a.Format.archive() && (len(files) != 1 || files[0].Dir) {
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
	if u.DownloadDir != "" {
		// Updaters sharing DownloadDir take turns on the same artifact.
		l, err := lockFile(ctx, download+".lock")
		if err != nil {
			return err
		}
		defer l.unlock()
	}
	f, err := Download(ctx, u.Source, a, download, u.Progress)
	if err != nil {
		return err
	}
	defer func() {
		closeQuietly(f)
		_ = os.Remove(download)
	}()
	targets := make([]string, len(files))
	for i, f := range files {
		targets[i] = f.Target
	}
	staged, err := j.Stage(ctx, targets...)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, staged.Abort(context.WithoutCancel(ctx))) }()
	var members []Member
	for i, p := range staged.Paths() {
		if fl := files[i]; !fl.Dir {
			members = append(members, Member{Name: fl.Member, Path: p, Mode: fl.Mode})
		}
	}
	if len(members) > 0 {
		if err := Extract(ctx, f, a.Size, a.Format, members, u.Extract); err != nil {
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
	if u.DryRun {
		return nil
	}
	return staged.Replace(ctx, ReplaceOptions{Version: c.Version, Previous: c.Current, Pending: pending})
}

// downloadKey names the download file after the content, so a resumed
// download never mixes two artifacts.
func downloadKey(a Artifact) string {
	if a.SHA512 != "" {
		return a.SHA512[:32]
	}
	return a.SHA256[:32]
}
