package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

type updaterEnv struct {
	fs  *fileServer
	key testKey
	exe string
}

func newUpdaterEnv(t *testing.T) *updaterEnv {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "app")
	if err := os.WriteFile(exe, []byte("app 1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &updaterEnv{fs: newFileServer(t), key: newTestKey(t), exe: exe}
}

// publish serves the releases with relative artifact URLs, signed by the
// env key, and returns an Updater for them.
func (e *updaterEnv) publish(t *testing.T, m *Manifest) *Updater {
	t.Helper()
	url := e.fs.put("manifest.json", mustSign(t, m, e.key))
	return &Updater{
		Source:     &HTTPSource{URL: url},
		Trust:      e.key.trust(),
		Now:        func() time.Time { return testNow },
		Product:    "app",
		Current:    "1.0.0",
		Executable: e.exe,
		OS:         "linux",
		Arch:       "amd64",
	}
}

func (e *updaterEnv) release(t *testing.T, version, channel string) Release {
	t.Helper()
	data := tarGz(t, true, tarEntry{name: "app", body: "app " + version}, tarEntry{name: "app.dat", body: "data " + version})
	name := "app-" + version + ".tar.gz"
	e.fs.put(name, data)
	a := artifactFor("app", name, FormatTarGzip, data)
	a.OS, a.Arch = "linux", "amd64"
	return Release{Version: version, Channel: channel, Artifacts: []Artifact{a}}
}

func TestUpdaterApplyCommit(t *testing.T) {
	e := newUpdaterEnv(t)
	u := e.publish(t, manifestOf("app", e.release(t, "1.1.0", ""), e.release(t, "1.0.5", "")))
	var progressed bool
	u.Progress = func(int64, int64) { progressed = true }
	c, err := u.Update(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "1.1.0" || c.Downgrade || !slices.Equal(c.KeyIDs, []string{KeyID(e.key.pub)}) || !progressed {
		t.Fatalf("candidate %+v", c)
	}
	if readFile(t, e.exe) != "app 1.1.0" {
		t.Fatal("not installed")
	}
	j, err := u.Journal()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := j.Startup(1); err != nil || out.Status != StatusPending || out.Version != "1.1.0" {
		t.Fatalf("startup %+v %v", out, err)
	}
	if err := j.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, filepath.Dir(e.exe)); !slices.Equal(got, []string{"app"}) {
		t.Errorf("dir %v", got)
	}
	u.Current = "1.1.0"
	if _, err := u.Check(t.Context()); !errors.Is(err, ErrUpToDate) {
		t.Errorf("same version: %v", err)
	}
}

func TestUpdaterSiblingFilesAndInstall(t *testing.T) {
	e := newUpdaterEnv(t)
	u := e.publish(t, manifestOf("app", e.release(t, "2.0.0", "")))
	u.Files = []File{{Member: "app", Target: "app"}, {Member: "app.dat", Target: "app.dat", Mode: 0o644}}
	if _, err := u.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, err := u.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Install(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(e.exe)
	if readFile(t, e.exe) != "app 2.0.0" || readFile(t, filepath.Join(dir, "app.dat")) != "data 2.0.0" {
		t.Fatal("not installed")
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"app", "app.dat"}) {
		t.Errorf("dir %v", got)
	}
}

func TestUpdaterRefusals(t *testing.T) {
	e := newUpdaterEnv(t)
	other := newTestKey(t)
	cases := map[string]struct {
		setup func(*Updater)
		want  error
		m     *Manifest
	}{
		"older only": {nil, ErrUpToDate, manifestOf("app", e.release(t, "0.9.0", ""))},
		"downgrade allowed": {func(u *Updater) { u.AllowDowngrade = true }, nil,
			manifestOf("app", e.release(t, "0.9.0", ""))},
		"prerelease hidden":  {nil, ErrUpToDate, manifestOf("app", e.release(t, "2.0.0-rc.1", ""))},
		"prerelease allowed": {func(u *Updater) { u.AllowPrerelease = true }, nil, manifestOf("app", e.release(t, "2.0.0-rc.1", ""))},
		"channel hidden":     {nil, ErrUpToDate, manifestOf("app", e.release(t, "2.0.0", "beta"))},
		"channel allowed":    {func(u *Updater) { u.Channels = []string{"beta"} }, nil, manifestOf("app", e.release(t, "2.0.0", "beta"))},
		"wrong product":      {nil, ErrWrongProduct, manifestOf("other", e.release(t, "2.0.0", ""))},
		"wrong platform":     {func(u *Updater) { u.OS = "windows" }, ErrUpToDate, manifestOf("app", e.release(t, "2.0.0", ""))},
		"untrusted":          {func(u *Updater) { u.Trust = other.trust() }, ErrUnsigned, manifestOf("app", e.release(t, "2.0.0", ""))},
		"no trust":           {func(u *Updater) { u.Trust = Trust{} }, ErrNoTrustedKeys, manifestOf("app", e.release(t, "2.0.0", ""))},
		"expired": {func(u *Updater) { u.Now = func() time.Time { return testNow.Add(48 * time.Hour) } }, ErrExpiredManifest,
			manifestOf("app", e.release(t, "2.0.0", ""))},
		"too large": {func(u *Updater) { u.MaxArtifactSize = 10 }, ErrTooLarge, manifestOf("app", e.release(t, "2.0.0", ""))},
		"authorize": {func(u *Updater) {
			u.Authorize = func(_ context.Context, c *Candidate) error {
				if c.Version == "2.0.0" {
					return errors.New("not now")
				}
				return nil
			}
		}, ErrRefused, manifestOf("app", e.release(t, "2.0.0", ""))},
		"bad current": {func(u *Updater) { u.Current = "" }, ErrInvalidVersion, manifestOf("app", e.release(t, "2.0.0", ""))},
	}
	for name, c := range cases {
		u := e.publish(t, c.m)
		if c.setup != nil {
			c.setup(u)
		}
		cand, err := u.Check(t.Context())
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
		if c.want == nil && name == "downgrade allowed" && (cand == nil || !cand.Downgrade) {
			t.Errorf("%s: downgrade not flagged", name)
		}
	}
	// Only candidates from Check are applied.
	u := e.publish(t, manifestOf("app", e.release(t, "2.0.0", "")))
	if err := u.Apply(t.Context(), &Candidate{Version: "9.0.0"}); !errors.Is(err, ErrNotChecked) {
		t.Errorf("forged candidate: %v", err)
	}
	if err := u.Apply(t.Context(), nil); !errors.Is(err, ErrNotChecked) {
		t.Errorf("nil candidate: %v", err)
	}
}

func TestUpdaterTamperedArtifact(t *testing.T) {
	e := newUpdaterEnv(t)
	r := e.release(t, "2.0.0", "")
	u := e.publish(t, manifestOf("app", r))
	evil := tarGz(t, true, tarEntry{name: "app", body: "evil 2.0.0"}, tarEntry{name: "app.dat", body: "data 2.0.0"})
	e.fs.put("app-2.0.0.tar.gz", evil)
	if _, err := u.Update(t.Context()); !errors.Is(err, ErrDigestMismatch) && !errors.Is(err, ErrTooLarge) {
		t.Fatalf("tampered artifact: %v", err)
	}
	if readFile(t, e.exe) != "app 1.0.0" {
		t.Fatal("tampered artifact installed")
	}
	if got := listDir(t, filepath.Dir(e.exe)); !slices.Equal(got, []string{"app"}) {
		t.Errorf("dir %v", got)
	}
}

func TestUpdaterDryRunAndResume(t *testing.T) {
	e := newUpdaterEnv(t)
	u := e.publish(t, manifestOf("app", e.release(t, "2.0.0", "")))
	u.DryRun = true
	u.DownloadDir = t.TempDir()
	if _, err := u.Update(t.Context()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, e.exe) != "app 1.0.0" || !slices.Equal(listDir(t, filepath.Dir(e.exe)), []string{"app"}) {
		t.Fatal("dry run changed files")
	}
	if len(listDir(t, u.DownloadDir)) != 0 {
		t.Error("download kept after success")
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "js" && runtime.GOOS != "wasip1" && os.Getuid() != 0 {
		ro := filepath.Join(t.TempDir(), "ro")
		must(t, os.Mkdir(ro, 0o555))
		u.Executable = filepath.Join(ro, "app")
		u.DryRun = false
		if _, err := u.Update(t.Context()); err == nil {
			t.Error("read-only directory accepted")
		}
	}
}

func TestUpdaterMinPublished(t *testing.T) {
	e := newUpdaterEnv(t)
	u := e.publish(t, manifestOf("app", e.release(t, "2.0.0", "")))
	u.MinPublished = testNow
	if _, err := u.Check(t.Context()); !errors.Is(err, ErrStaleManifest) {
		t.Fatalf("old manifest: %v", err)
	}
	u.MinPublished = testNow.Add(-2 * time.Hour)
	if _, err := u.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestUpdaterSharedDownloadDir(t *testing.T) {
	e := newUpdaterEnv(t)
	u := e.publish(t, manifestOf("app", e.release(t, "2.0.0", "")))
	u.DownloadDir = t.TempDir()
	c, err := u.Check(t.Context())
	must(t, err)
	l, err := acquireLock(filepath.Join(u.DownloadDir, "selfupdate-"+downloadKey(c.artifact)+".download.lock"))
	must(t, err)
	if err := u.Apply(t.Context(), c); !errors.Is(err, ErrBusy) {
		t.Errorf("shared download: %v", err)
	}
	must(t, l.release())
	must(t, u.Apply(t.Context(), c))
	if readFile(t, e.exe) != "app 2.0.0" {
		t.Fatal("not installed")
	}
}
