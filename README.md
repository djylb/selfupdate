# selfupdate

Package `selfupdate` lets a Go program update itself and the data files it
depends on: daemons, command-line tools, agents on servers, desktop programs
and small devices alike. It uses the standard library only.

```
go get github.com/djylb/selfupdate
```

## What it does

- **Release discovery.** A `Source` returns a signed manifest. `HTTPSource`
  fetches one from a URL — a `manifest.json` in a static directory next to
  the artifacts it lists by relative URL is enough. Implement `Source` for
  anything else; it need not be trusted.
- **Signatures.** Manifests are signed with Ed25519. Clients trust a list of
  keys (identified by key IDs), may require several signatures, and may give
  a key an end of validity to retire it during rotation. Detached
  signatures over a single file are available too (`SignArtifact`,
  `VerifyArtifact`).
- **Versions.** Semantic versions with full pre-release ordering
  (`ParseVersion`, `CompareVersions`). Pre-releases and extra channels are
  opt-in.
- **Downloads.** `Download` takes a context and your `http.Client`, bounds
  the size, resumes interrupted downloads, hashes as it streams and reports
  progress. SHA-256 and SHA-512 are supported.
- **Archives.** `Extract` takes named files out of raw, `.gz`, `.tar`,
  `.tar.gz` and `.zip` artifacts; `ExtractDir` unpacks a whole tree with
  path checks. Symlinks, hard links, devices, duplicates and size bombs are
  rejected.
- **Replacement.** A `Journal` swaps a set of files by rename in their own
  directories, keeps backups, and either commits or rolls back — also after
  a crash or power loss at any point: the journal names every path up front
  and is replaced atomically, and recovery can be repeated any number of
  times. A lock file serializes journal operations across processes; a lock
  left by a dead process is broken automatically.
- **Health-checked commit.** An update starts *pending*. The new version
  confirms itself with `Commit` once it is healthy; a start that does not
  is rolled back by the next one.
- **Restart.** `Relaunch` re-executes the program in place on Unix and
  starts a successor on Windows.
- **Policy.** An `Authorize` hook sees every candidate (version, channel,
  signers, URL) and can refuse it.

## Threat model

The update channel is assumed hostile: the server, the network, mirrors and
caches may serve anything. The signing key is the only root of trust.

| Threat | Defence |
| --- | --- |
| Modified or substituted artifact | The signed manifest pins the exact size and digest of every artifact; content is checked before it is unpacked. |
| Forged manifest | Ed25519 signature over the exact payload bytes, with a context prefix; unsigned manifests are rejected unless `Trust.InsecureSkipSignature` is set. |
| Hash and package from the same place | Digests come only from the signed manifest, never from a file next to the artifact. |
| Rollback to an old, vulnerable release | Releases older than the running one are refused unless `AllowDowngrade` is set. |
| Replay of an old signed manifest (freeze) | Every manifest must carry an expiry; expired manifests are rejected. `MinPublished` rejects manifests older than one already seen. |
| Ambiguous signed JSON | The payload is decoded strictly: unknown fields, duplicate keys and trailing data are rejected, so every reader sees the same content. |
| Manifest of one product applied to another | The manifest names its product and the client checks it. |
| Compromised or retired key | Keys are listed explicitly; remove one or let its `NotAfter` pass. `Threshold` can demand several signers. |
| Archive path traversal ("zip slip"), links | `Extract` takes output paths from the caller only; `ExtractDir` checks every name with `filepath.Localize` and refuses links and devices. |
| Decompression bombs | Per-file, total and entry-count limits. |
| Remote party forcing an update | `Authorize` hook, channel and pre-release opt-in. |
| Broken release | Pending state, health-checked commit, automatic rollback. |
| Crash or power loss mid-update | Journal written atomically before any rename, directories synced; the next start finishes or undoes it. |
| Concurrent updaters | Lock file per journal and per shared download; a second update gets `ErrBusy`. |

Out of scope: an attacker who can write to the program's directory or holds
the signing key; protecting the clock (a wrong clock weakens expiry checks).

## Publishing

Create a key once and keep the private half offline:

```
go run github.com/djylb/selfupdate/cmd/selfupdate keygen -out release.key
```

It prints the public key (`ed25519:...`) to compile into the program. For
each release, describe each artifact and sign the manifest:

```
selfupdate artifact -name app -os linux -arch amd64 -format tar.gz \
    -url app_1.5.0_linux_amd64.tar.gz dist/app_1.5.0_linux_amd64.tar.gz
selfupdate sign -key release.key -expires 720h -in manifest.json -out dist/manifest.json
```

`manifest.json` is the JSON form of `Manifest`:

```jsonc
{
  "product": "app",
  "releases": [
    {"version": "1.5.0", "artifacts": [ /* output of "selfupdate artifact" */ ]},
    {"version": "1.6.0-rc.1", "channel": "beta", "artifacts": [ ]}
  ]
}
```

Re-sign the manifest before it expires, even without a new release. To
rotate keys, release a version trusting both keys, sign with both for a
while, then sign with the new key only. `SignManifest` does the same from Go.

## Using it

Call `Startup` first on every start, before real work:

```go
j, err := selfupdate.ExecutableJournal()
if err != nil { ... }
out, err := j.Startup(1)
if err != nil { ... }
switch out.Status {
case selfupdate.StatusPending:
	// First start of a new version: check health, then confirm.
	if selfCheck() == nil {
		err = j.Commit()
	}
case selfupdate.StatusRolledBack:
	// The previous files are back; run them.
	return selfupdate.Relaunch(exe, os.Args)
case selfupdate.StatusIdle:
}
```

`Startup(n)` allows `n` starts without a commit; the next one rolls back.
Only real starts should count: runs that do not exercise the program, such
as `--version` or `--help`, should call `Recover` instead, which finishes
interrupted work but leaves a pending update's count alone. Committing after
the process has run for a while, or after it has served its first request,
is common.

Check for and apply updates:

```go
u := &selfupdate.Updater{
	Source:  &selfupdate.HTTPSource{URL: "https://updates.example.com/app/manifest.json"},
	Trust:   selfupdate.Trust{Keys: []selfupdate.TrustedKey{{Public: releaseKey}}},
	Product: "app",
	Current: version,
}
c, err := u.Check(ctx)          // or u.Update(ctx) to check and apply
if errors.Is(err, selfupdate.ErrUpToDate) { return nil }
if err != nil { return err }
if err := u.Apply(ctx, c); err != nil { return err }
// restart into c.Version
```

By default `Apply` replaces the executable with the archive member named
like it (`app`, or `app.exe` on Windows). Set `Files` to install several
files from one artifact as one set, such as a program and its plugins.
`DryRun` stops after verification and staging. `DownloadDir` keeps partial
downloads so they resume. Record `Candidate.Published` after an update and
pass it as `MinPublished` later to resist freeze attacks. Installed files
keep the permission bits of the files they replace; setuid, setgid and
sticky bits are never carried over.

Data files, such as rule databases, use a second `Updater` with their own
product, version and `Files`, and `Install`, which has no pending step:

```go
rules := &selfupdate.Updater{
	Source: src, Trust: trust,
	Product: "rules", Current: currentRulesVersion,
	Files: []selfupdate.File{{Target: "/var/lib/app/rules.db", Mode: 0o644}},
}
```

The building blocks — `OpenManifest`, `Download`, `Artifact.Check`,
`Extract`, `Journal.Stage` and `Journal.Replace` — can be used directly for
other flows. `Stage` records the staging paths before the new files are
written, so a crash while writing them leaves nothing behind.

## Restarting and service managers

`Relaunch` replaces the process image on Unix (same PID, so a service
manager sees nothing). On Windows it starts the new process and returns;
exit right after.

Under a service manager it is usually simpler to exit after `Apply` and let
the manager start the new version: configure it to restart the service on
exit (for example "restart always" policies, or recovery actions on
Windows). `selfupdate` does not install or control services. If the new
version cannot even reach `Startup`, nothing rolls it back automatically;
a supervisor or a pre-start hook can call `JournalFor(exe).Startup` on the
program's behalf, or `Rollback` to undo a pending update. A journal damaged
from outside is reported as `ErrCorruptJournal` and never guessed at:
restore from the `*.selfupdate-old` backups by hand and delete it.

## Windows notes

- A running executable cannot be overwritten or deleted, but it can be
  renamed. The journal renames it aside, moves the new file in, and deletes
  the old one on commit. When that is not yet possible (the old process is
  still exiting), the file is kept in the journal and deleted by a later
  start.
- Renames are retried briefly when a scanner or indexer holds a file open.
- After `Relaunch` the old and new processes overlap for a moment; the new
  one should retry ports and other exclusive resources.
- File ownership is not copied; new files inherit the directory's ACL.

## Platform support

All Go targets build. File replacement and journaling work everywhere a
file system is available; `Relaunch` returns `errors.ErrUnsupported` where
processes cannot be started (js/wasm, wasip1, plan9).

## License

Apache License 2.0.
