// Package selfupdate lets a program update itself and the files it depends
// on, safely and from any release source.
//
// The pieces fit together as a pipeline, and each can be used alone:
//
//   - a [Source] provides a signed [Manifest] and the artifacts it lists;
//     [HTTPSource] reads them over HTTP, [DirSource] from a local
//     directory, and publishers produce manifests with [SignManifest];
//   - [OpenManifest] verifies Ed25519 signatures against a [Trust] policy
//     with key IDs, several keys, thresholds and key expiry, and rejects
//     expired manifests;
//   - [Version] and [CompareVersions] order semantic versions;
//   - [Download] fetches an artifact from a Source with resumption, a size
//     bound and progress, and returns it verified against the manifest;
//   - [Extract] and [ExtractDir] unpack raw, gzip, tar, tar.gz and zip
//     files without letting entry names choose output paths;
//   - a [Journal] swaps a set of files and directories by rename, keeps
//     backups, and commits or rolls back, also after a crash;
//   - [Relaunch] restarts the program on the new code.
//
// [Updater] composes them. A program that updates itself calls
// [Journal.Startup] early on every real start ([Journal.Recover] for runs
// such as printing its version):
//
//	j, err := selfupdate.ExecutableJournal()
//	...
//	out, err := j.Startup(ctx, 1)
//	switch out.Status {
//	case selfupdate.StatusPending:
//		// run a self-check, then j.Commit(ctx)
//	case selfupdate.StatusRolledBack:
//		// skip out.Version from now on; selfupdate.Relaunch("", nil)
//	case selfupdate.StatusIdle, selfupdate.StatusInProgress, selfupdate.StatusCleanup:
//	}
//
// Everything fails closed: unsigned or tampered manifests, artifacts
// without digests, older releases and expired manifests are rejected
// unless the caller opts in explicitly.
package selfupdate
