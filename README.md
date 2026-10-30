# selfupdate

Package `selfupdate` lets a Go program update itself and the data files it
depends on: daemons, command-line tools, agents on servers, desktop programs
and small devices alike. It uses the standard library only.

```
go get github.com/djylb/selfupdate
```

## What it does

- **Release sources.** A `Source` returns the signed manifest and opens the
  artifacts it lists. `HTTPSource` reads both over HTTP — a `manifest.json`
  in a static directory next to the artifacts it lists by relative URL is
  enough — and resumes downloads with range requests. `DirSource` reads
  them from a local directory, such as a mounted drive, for offline and
  air-gapped updates. Implement `Source` for anything else (an API, object
  storage, a peer); nothing it returns is trusted before it is verified.
- **Signatures.** Manifests are signed with Ed25519. Clients trust a list of
  keys (identified by key IDs), may require several signatures, and may give
  a key an end of validity to retire it during rotation. Detached
  signatures over a single file are available too (`SignArtifact`,
  `VerifyArtifact`).
- **Versions.** Semantic versions with full pre-release ordering
  (`ParseVersion`, `CompareVersions`). Pre-releases and extra channels are
  opt-in; `Skip` hides releases, such as one that was rolled back.
- **Downloads.** `Download` bounds the size, resumes interrupted downloads,
  hashes as it streams (only the digests the artifact lists, SHA-256 and
  SHA-512 supported), reports progress and returns the verified file open,
  so the content that is unpacked is the content that was checked.
- **Archives.** `Extract` takes named files out of raw, `.gz` (also
  multi-member), `.tar`, `.tar.gz` and `.zip` artifacts; `ExtractDir`
  unpacks a whole tree with path checks. Symlinks, hard links, devices,
  duplicates and size bombs are rejected. Both can be cancelled and report
  progress.
- **Replacement.** A `Journal` swaps a set of files and directories by
  rename in their own directories, keeps backups, and either commits or
  rolls back — also after a crash or power loss at any point: the journal
  names every path up front and is replaced atomically, and recovery can be
  repeated any number of times. Journal operations are serialized by
  operating system file locks, which the kernel releases when a process
  dies, so a crash never leaves a stale lock behind.
- **Health-checked commit.** An update starts *pending*. The new version
  confirms itself with `Commit` once it is healthy; a start that does not
  is rolled back by the next one.
- **Restart.** `Relaunch` re-executes the program in place on Unix and
  starts a successor on Windows.
- **Policy.** `OnManifest` sees every verified manifest and `Authorize`
  every candidate (version, channel, signers, artifact); either can refuse.

## Threat model

The update channel is assumed hostile: the server, the network, mirrors and
caches may serve anything. The signing key is the only root of trust.

| Threat | Defence |
| --- | --- |
| Modified or substituted artifact | The signed manifest pins the exact size and digest of every artifact; content is checked before it is unpacked, and unpacked from the same open file. |
| Forged manifest | Ed25519 signature over the exact payload bytes, with a context prefix; unsigned manifests are rejected unless `Trust.InsecureSkipSignature` is set. |
| Hash and package from the same place | Digests come only from the signed manifest, never from a file next to the artifact. |
| Rollback to an old, vulnerable release | Releases older than the running one are refused unless `AllowDowngrade` is set. |
| Replay of an old signed manifest (freeze) | Every manifest must carry a publication time and an expiry; expired manifests are rejected. `MinPublished` rejects manifests older than one already seen. |
| Ambiguous signed JSON | The payload is decoded strictly: unknown fields, duplicate keys and trailing data are rejected, and so are releases listed twice or artifacts that match the same platform, so every reader sees the same content. |
| Manifest of one product applied to another | The manifest names its product and the client checks it. |
| Compromised or retired key | Keys are listed explicitly; remove one or let its `NotAfter` pass. `Threshold` can demand several signers. |
| Archive path traversal ("zip slip"), links | `Extract` takes output paths from the caller only; `ExtractDir` and `DirSource` check every name with `filepath.Localize` and refuse links and devices. |
| Decompression bombs | Per-file, total and entry-count limits. |
| Remote party forcing an update | `Authorize` hook, channel and pre-release opt-in. |
| Broken release | Pending state, health-checked commit, automatic rollback, `Skip` for releases that were rolled back. |
| Crash or power loss mid-update | Journal written atomically before any rename, directories synced; the next start finishes or undoes it. |
| Concurrent updaters | Operating system locks per journal and per shared download; concurrent journal operations wait their turn, a second update gets `ErrBusy`. |

Out of scope: an attacker who can write to the program's directory or holds
the signing key; protecting the clock (a wrong clock weakens expiry checks).

## Publishing

Create a key once and keep the private half offline:

```
go run github.com/djylb/selfupdate/cmd/selfupdate keygen -out release.key
```

It prints the public key (`ed25519:...`) to compile into the program;
`selfupdate pubkey -key release.key` prints it again. For each release,
add each artifact to the manifest and sign it:

```
selfupdate artifact -name app -os linux -arch amd64 -member app \
    -into manifest.json -version 1.5.0 dist/app_1.5.0_linux_amd64.tar.gz
selfupdate sign -key release.key -expires 720h -in manifest.json -out dist/manifest.json
selfupdate verify -pub ed25519:... -in dist/manifest.json -dist dist
```

The format follows from the file name (`-format raw` is needed for plain
files), `-member` checks that the archive holds the program, and the URL
defaults to the file name, relative to the manifest. `verify -dist dir`
checks the size and digests of every artifact with a relative URL against
its file below `dir`; artifacts with absolute `http`/`https` URLs are
downloaded and checked the same way with `-fetch`. An artifact the given
flags do not cover makes `verify` fail and lists it, so a pass means every
artifact was checked. `manifest.json` is the
JSON form of `Manifest`, read as strictly as clients read it:

```jsonc
{
  "product": "app",
  "releases": [
    {"version": "1.5.0", "artifacts": [ /* added by "selfupdate artifact" */ ]},
    {"version": "1.6.0-rc.1", "channel": "beta", "artifacts": [ ]}
  ]
}
```

`sign` sets the publication time to now and the expiry to now plus
`-expires`; re-sign before the manifest expires, even without a new release
(the output of `verify` can be signed again). To rotate keys, release a
version trusting both keys, sign with both for a while, then sign with the
new key only. `SignManifest` does the same from Go; `sign-file` and
`verify-file` handle detached signatures.

## Using it

Call `Startup` on the updater's journal first on every start, before real
work:

```go
j, err := selfupdate.ExecutableJournal() // or u.Journal if you set it
if err != nil { ... }
out, err := j.Startup(ctx, 1)
if err != nil { ... }
switch out.Status {
case selfupdate.StatusPending:
	// First start of a new version: check health, then confirm.
	if selfCheck() == nil {
		err = j.Commit(ctx)
	}
case selfupdate.StatusRolledBack:
	// The previous files are back: remember out.Version to skip it, and
	// run the old code.
	return selfupdate.Relaunch("", nil)
}
```

`Startup(ctx, n)` allows `n` starts without a commit; the next one rolls
back. Only real starts should count: runs that do not exercise the program,
such as `--version` or `--help`, should call `Recover` instead, which
finishes interrupted work but leaves a pending update's count alone. With
no update in flight both only look for the journal and for lock files a
dead process left, which they try to delete: they need no write access. Committing after the process has run for a
while, or after it has served its first request, is common. The context
bounds only the wait for another process's journal operation.

Check for and apply updates:

```go
u := &selfupdate.Updater{
	Source:  &selfupdate.HTTPSource{URL: "https://updates.example.com/app/manifest.json"},
	Trust:   selfupdate.Trust{Keys: []selfupdate.TrustedKey{{Public: releaseKey}}},
	Product: "app",
	Current: version,
	MinPublished: settings.MinPublished,
	OnManifest: func(_ context.Context, o *selfupdate.Opened) error {
		settings.MinPublished = o.Manifest.Published // persist it
		return nil
	},
	Skip: func(v string) bool { return slices.Contains(settings.RolledBack, v) },
}
c, err := u.Check(ctx)          // or u.Update(ctx) to check and apply
switch {
case errors.Is(err, selfupdate.ErrUpToDate), errors.Is(err, selfupdate.ErrPendingRestart):
	return nil
case err != nil:
	return err // ErrNoArtifact: no build for this name and platform
}
if err := u.Apply(ctx, c); err != nil { return err }
// restart into c.Version
```

By default `Apply` replaces the executable with the archive member named
like it (`app`, or `app.exe` on Windows). Set `Files` to install several
files, or whole directories (`Dir`), from one artifact as one set, such as
a program and its plugins or web assets. The journal stays next to the
executable whatever `Files` lists. `DryRun` stops after verification and
staging. `DownloadDir` keeps partial downloads so they resume. While an
update is pending or in progress, or a finished one left files that cannot
be deleted yet (`Peek` reports `StatusCleanup`), `Apply` fails at once with
`ErrBusy` instead of downloading again, and checking for the pending version itself gives
`ErrPendingRestart`. Installed files keep the permission bits of the files
they replace; new files get `Mode` (default 0o644, 0o755 for the default
executable); setuid, setgid and sticky bits are never carried over.

Data files, such as rule databases, use a second `Updater` with their own
product, version, `Files` and journal, and `Install`, which has no pending
step:

```go
rules := &selfupdate.Updater{
	Source: src, Trust: trust,
	Product: "rules", Current: currentRulesVersion,
	Files:   []selfupdate.File{{Target: "/var/lib/app/rules.db"}},
	Journal: selfupdate.JournalFor("/var/lib/app/rules.db"),
}
```

The building blocks — `OpenManifest`, `Download`, `Artifact.Check`,
`Extract`, `ExtractDir`, `Journal.Stage` and `Journal.Replace` — can be
used directly for other flows. `Stage` records the staging paths before the
new files are written, so a crash while writing them leaves nothing behind;
defer `Staged.Abort`, which does nothing after a successful `Replace`.
`Journal.Peek` reports the state without changing anything, for status
displays.

## Restarting and service managers

`Relaunch("", nil)` restarts the running executable with its arguments: it
replaces the process image on Unix (same PID, so a service manager sees
nothing). On Windows it starts the new process and returns; exit with
status zero right after.

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
- Other files cannot be renamed while a process has them open: close data
  files, and every file in a directory being replaced, before installing.
- Renames are retried while a scanner or indexer holds a file open, for
  `Journal.RenameRetry` (10 seconds by default).
- After `Relaunch` the old and new processes overlap for a moment; the new
  one should retry ports and other exclusive resources.
- File ownership is not copied; new files inherit the directory's ACL.

## Platform support

All Go targets build. File replacement and journaling work everywhere a
file system is available. Locks use `flock` on most Unix systems, `fcntl`
on Solaris, illumos and AIX (where the library also keeps two opens of one
lock file in one process apart, since `fcntl` locks belong to the process), and `LockFileEx` on Windows; js/wasm, wasip1
and plan9 have no usable file locks, so there locks only exclude the
goroutines of one process: run one updating instance at a time. `Relaunch`
returns `errors.ErrUnsupported` where processes cannot be started (js/wasm,
wasip1, plan9).

## License

Apache License 2.0.
