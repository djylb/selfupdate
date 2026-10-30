package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"
)

// Errors returned by [Updater].
var (
	ErrUpToDate      = errors.New("selfupdate: no newer release")
	ErrWrongProduct  = errors.New("selfupdate: manifest is for another product")
	ErrRefused       = errors.New("selfupdate: update refused by policy")
	ErrNotChecked    = errors.New("selfupdate: candidate did not come from Check")
	ErrStaleManifest = errors.New("selfupdate: manifest older than one seen before")
)

// File selects one file of an artifact and where to install it.
type File struct {
	// Member names the file inside an archive artifact; see [Member].
	Member string
	// Target is the installed path. A relative path is relative to the
	// directory of the executable.
	Target string
	// Mode is used when Target does not exist yet; an existing target
	// keeps its own permissions. Zero means 0o755.
	Mode fs.FileMode
}

// Candidate is a release chosen by [Updater.Check]. Its exported fields
// describe it; changing them does not change what [Updater.Apply] installs.
type Candidate struct {
	// Published is the publication time of the manifest.
	Published time.Time
	// URL is the resolved artifact URL.
	URL *url.URL
	// Product, Version and Channel identify the release.
	Product, Version, Channel string
	// Current is the version being replaced.
	Current string
	// Notes is the release notes.
	Notes string
	// KeyIDs lists the trusted keys that signed the manifest.
	KeyIDs []string
	// Size is the artifact size in bytes.
	Size     int64
	artifact Artifact
	// Downgrade is set when Version is older than Current, which
	// [Updater.AllowDowngrade] must permit.
	Downgrade bool
	checked   bool
}

// Updater checks for, downloads, verifies and installs updates. The
// fields configure it; set them before first use and do not change them
// while a method runs. Methods may run concurrently: an update in flight
// holds the journal, so a second one fails with [ErrBusy].
//
// The typical program calls [Journal.Startup] (see [ExecutableJournal])
// first thing, commits after a health check when the status is pending,
// and from time to time calls [Updater.Update] and restarts.
type Updater struct {
	// Source finds the signed manifest. Required.
	Source Source
	// Authorize, when set, sees each candidate and may refuse it by
	// returning an error. It runs on the calling goroutine with no lock
	// held. Use it when a remote party must not be able to force updates,
	// for example to ask a user or to allow only some signers.
	Authorize func(ctx context.Context, c *Candidate) error
	// Client downloads artifacts; nil means [http.DefaultClient].
	Client *http.Client
	// Progress observes downloads; may be nil.
	Progress ProgressFunc
	// Now returns the current time for expiry checks; nil means
	// [time.Now].
	Now func() time.Time
	// MinPublished, when set, rejects manifests published before it. Store
	// [Candidate.Published] of each installed update and pass it here, so
	// that an attacker cannot serve an older, still unexpired manifest to
	// hide a newer release (a freeze attack) for longer than the gap
	// between releases.
	MinPublished time.Time
	// Trust is the signature policy. Its zero value rejects everything.
	Trust Trust
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
	// the next attempt. Empty means a temporary directory per call, which
	// is removed afterwards.
	DownloadDir string
	// Channels lists the release channels accepted besides the default
	// channel.
	Channels []string
	// Files selects what to install. Empty means one file: the executable,
	// taken from the archive member named like the executable.
	Files []File
	// Limits bounds archive extraction.
	Limits Limits
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

// Check fetches and verifies the manifest and returns the release to
// install, or [ErrUpToDate].
func (u *Updater) Check(ctx context.Context) (*Candidate, error) {
	if u.Source == nil || u.Product == "" {
		return nil, errors.New("selfupdate: Updater needs Source and Product")
	}
	current, err := ParseVersion(u.Current)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: current version %q: %w", u.Current, err)
	}
	fetched, err := u.Source.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	opened, err := OpenManifest(fetched.Data, u.Trust, u.now())
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
	goos, goarch := u.platform()
	var best *Release
	var bestV Version
	var bestA Artifact
	for i := range m.Releases {
		r := &m.Releases[i]
		v, _ := ParseVersion(r.Version) // validated by OpenManifest
		if !u.channelOK(r.Channel) || (v.IsPrerelease() && !u.AllowPrerelease) {
			continue
		}
		a, ok := r.Artifact(u.name(), goos, goarch)
		if !ok {
			continue
		}
		if best == nil || v.Compare(bestV) > 0 {
			best, bestV, bestA = r, v, a
		}
	}
	if best == nil {
		return nil, ErrUpToDate
	}
	order := bestV.Compare(current)
	if order == 0 || (order < 0 && !u.AllowDowngrade) {
		return nil, ErrUpToDate
	}
	maxSize := u.MaxArtifactSize
	if maxSize <= 0 {
		maxSize = 1 << 30
	}
	if bestA.Size > maxSize {
		return nil, fmt.Errorf("%w: artifact of %d bytes", ErrTooLarge, bestA.Size)
	}
	loc, err := resolve(fetched.Base, bestA.URL)
	if err != nil {
		return nil, err
	}
	c := &Candidate{
		Published: m.Published,
		URL:       loc,
		Product:   m.Product,
		Version:   best.Version,
		Channel:   best.Channel,
		Current:   u.Current,
		Notes:     best.Notes,
		KeyIDs:    opened.KeyIDs,
		Size:      bestA.Size,
		Downgrade: order < 0,
		artifact:  bestA,
		checked:   true,
	}
	c.artifact.URL = loc.String()
	if u.Authorize != nil {
		if err := u.Authorize(ctx, c); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}
	return c, nil
}

func resolve(base *url.URL, ref string) (*url.URL, error) {
	r, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("%w: artifact url: %w", ErrMalformedManifest, err)
	}
	if base != nil {
		r = base.ResolveReference(r)
	}
	if r.Scheme != "http" && r.Scheme != "https" {
		return nil, fmt.Errorf("%w: artifact url %q is not http or https", ErrMalformedManifest, r.Redacted())
	}
	return r, nil
}

// Update runs [Updater.Check] and [Updater.Apply]. It returns the
// installed candidate, or [ErrUpToDate].
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
// the program afterwards to run the new version.
func (u *Updater) Apply(ctx context.Context, c *Candidate) error {
	return u.install(ctx, c, true)
}

// Install installs c at once, with no confirmation step. It suits data
// files, such as rule databases, and programs that do not check their own
// health. The replaced files are deleted when the swap succeeds.
func (u *Updater) Install(ctx context.Context, c *Candidate) error {
	return u.install(ctx, c, false)
}

// ExecutableJournal returns the journal of the running executable, the one
// [Updater.Apply] uses when [Updater.Files] is empty.
func ExecutableJournal() (Journal, error) {
	exe, err := executable("")
	if err != nil {
		return Journal{}, err
	}
	return JournalFor(exe), nil
}

// Journal returns the journal the updater records its updates in: the one
// next to its first target.
func (u *Updater) Journal() (Journal, error) {
	files, err := u.files()
	if err != nil {
		return Journal{}, err
	}
	return JournalFor(files[0].Target), nil
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
		if f.Mode == 0 {
			f.Mode = 0o755
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
	if c == nil || !c.checked {
		return ErrNotChecked
	}
	files, err := u.files()
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := CheckWritable(filepath.Dir(f.Target)); err != nil {
			return err
		}
	}
	dir := u.DownloadDir
	if dir == "" {
		if dir, err = os.MkdirTemp("", "selfupdate-"); err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
	}
	a := c.artifact
	download := filepath.Join(dir, "selfupdate-"+downloadKey(a)+".download")
	// Updaters sharing DownloadDir take turns on the same artifact.
	l, err := acquireLock(download + ".lock")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, l.release()) }()
	d, err := Download(ctx, u.Client, a.URL, download, a.Size, u.Progress)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(download) }()
	if err := a.Check(a.Size, d); err != nil {
		return err
	}
	targets := make([]string, len(files))
	for i, f := range files {
		targets[i] = f.Target
	}
	staged, err := JournalFor(files[0].Target).Stage(targets...)
	if err != nil {
		return err
	}
	members := make([]Member, len(files))
	for i, p := range staged.Paths() {
		members[i] = Member{Name: files[i].Member, Path: p, Mode: files[i].Mode}
	}
	if err := Extract(download, a.Format, members, u.Limits); err != nil {
		return errors.Join(err, staged.Abort())
	}
	if u.DryRun {
		return staged.Abort()
	}
	if err := staged.Replace(ReplaceOptions{Version: c.Version, Previous: c.Current, Pending: pending}); err != nil {
		return errors.Join(err, staged.Abort())
	}
	return nil
}

// downloadKey names the download file after the content, so a resumed
// download never mixes two artifacts.
func downloadKey(a Artifact) string {
	if a.SHA512 != "" {
		return a.SHA512[:32]
	}
	return a.SHA256[:32]
}
