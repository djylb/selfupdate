// Package selfupdate lets a program update itself and the files it depends
// on, safely and from any release source.
//
// The pieces fit together as a pipeline, and each can be used alone:
//
//   - a [Source] fetches a signed [Manifest]; [HTTPSource] reads one from a
//     URL, and publishers produce it with [SignManifest];
//   - [OpenManifest] verifies Ed25519 signatures against a [Trust] policy
//     with key IDs, several keys, thresholds and key expiry, and rejects
//     expired manifests;
//   - [Version] and [CompareVersions] order semantic versions;
//   - [Download] fetches an artifact with resumption, a size bound and
//     progress, hashing as it goes; [Artifact.Check] compares the digests;
//   - [Extract] and [ExtractDir] unpack raw, gzip, tar, tar.gz and zip
//     files without letting entry names choose output paths;
//   - a [Journal] swaps a set of files by rename, keeps backups, and
//     commits or rolls back, also after a crash;
//   - [Relaunch] restarts the program on the new code.
//
// [Updater] composes them. A program that updates itself calls
// [Journal.Startup] early on every real start ([Journal.Recover] for runs
// such as printing its version):
//
//	j, err := selfupdate.ExecutableJournal()
//	...
//	out, err := j.Startup(1)
//	switch out.Status {
//	case selfupdate.StatusPending:
//		// run a self-check, then j.Commit()
//	case selfupdate.StatusRolledBack:
//		// restart into the restored version
//	case selfupdate.StatusIdle:
//	}
//
// Everything fails closed: unsigned or tampered manifests, artifacts
// without digests, older releases and expired manifests are rejected
// unless the caller opts in explicitly.
package selfupdate
