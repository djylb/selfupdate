package selfupdate_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/djylb/selfupdate"
)

// The release key's public half, compiled into the program.
const releaseKey = "ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

// Example shows the life cycle of a program that updates itself.
func Example() {
	// First thing on every start: finish or undo an earlier update.
	j, err := selfupdate.ExecutableJournal()
	if err != nil {
		log.Fatal(err)
	}
	out, err := j.Startup(1)
	if err != nil {
		log.Fatal(err)
	}
	switch out.Status {
	case selfupdate.StatusPending:
		// Running the new version for the first time: check health, then
		// confirm. Exiting without Commit rolls back on the next start.
		if err := j.Commit(); err != nil {
			log.Print(err)
		}
	case selfupdate.StatusRolledBack:
		// The old files are back; run them.
		log.Fatal(selfupdate.Relaunch(os.Args[0], os.Args))
	case selfupdate.StatusIdle:
	}

	pub, err := selfupdate.ParsePublicKey(releaseKey)
	if err != nil {
		log.Fatal(err)
	}
	u := &selfupdate.Updater{
		Source:  &selfupdate.HTTPSource{URL: "https://updates.example.com/app/manifest.json"},
		Trust:   selfupdate.Trust{Keys: []selfupdate.TrustedKey{{Public: pub}}},
		Product: "app",
		Current: "1.4.2",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	c, err := u.Update(ctx)
	cancel()
	switch {
	case errors.Is(err, selfupdate.ErrUpToDate):
		return
	case err != nil:
		log.Print(err)
		return
	}
	log.Printf("installed %s, restarting", c.Version)
	if err := selfupdate.Relaunch(os.Args[0], os.Args); err == nil {
		os.Exit(0) // Windows: the new process has started
	}
}

// ExampleSignManifest shows how a publisher produces a manifest.
func ExampleSignManifest() {
	_, priv, err := selfupdate.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	binary := []byte("the linux/amd64 build")
	d := selfupdate.DigestsOf(binary)
	m := &selfupdate.Manifest{
		Product:   "app",
		Published: time.Now(),
		Expires:   time.Now().Add(30 * 24 * time.Hour),
		Releases: []selfupdate.Release{{
			Version: "1.5.0",
			Artifacts: []selfupdate.Artifact{{
				Name: "app", OS: "linux", Arch: "amd64",
				URL:    "app-1.5.0-linux-amd64",
				Size:   int64(len(binary)),
				SHA256: fmt.Sprintf("%x", d.SHA256),
				Format: selfupdate.FormatRaw,
			}},
		}},
	}
	signed, err := selfupdate.SignManifest(m, priv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(signed) > 0)
	// Output: true
}

// ExampleUpdater_Install updates a data file, such as a rule database,
// with no confirmation step.
func ExampleUpdater_Install() {
	pub, _ := selfupdate.ParsePublicKey(releaseKey)
	u := &selfupdate.Updater{
		Source:  &selfupdate.HTTPSource{URL: "https://updates.example.com/rules/manifest.json"},
		Trust:   selfupdate.Trust{Keys: []selfupdate.TrustedKey{{Public: pub}}},
		Product: "rules",
		Current: "2026.10.1",
		Files:   []selfupdate.File{{Target: "/var/lib/app/rules.db", Mode: 0o644}},
	}
	ctx := context.Background()
	c, err := u.Check(ctx)
	if err != nil {
		return
	}
	if err := u.Install(ctx, c); err != nil {
		log.Print(err)
	}
}

func ExampleCompareVersions() {
	c, _ := selfupdate.CompareVersions("1.0.0-rc.2", "1.0.0")
	fmt.Println(c)
	// Output: -1
}
