// Command selfupdate creates keys, describes artifacts and signs and
// checks manifests for the selfupdate package.
//
// Usage:
//
//	selfupdate keygen -out release.key
//	selfupdate pubkey -key release.key
//	selfupdate artifact -name app -os linux -arch amd64 [-format tar.gz] [-url URL] [-member app]
//	        [-into manifest.json -version 1.5.0 [-channel beta] [-notes text]] dist/app_linux_amd64.tar.gz
//	selfupdate sign -key release.key [-expires 720h] [-in manifest.json] [-out manifest.signed.json]
//	selfupdate verify -pub ed25519:... [-in manifest.signed.json] [-dist dir] [-fetch]
//	selfupdate sign-file -key release.key [-out file.sig] file
//	selfupdate verify-file -pub ed25519:... -sig file.sig file
//
// The manifest given to sign is the JSON form of selfupdate.Manifest, read
// as strictly as clients read it. Signing always sets "published" to now
// and "expires" to now plus -expires, so re-signing the output of verify
// renews it. -format defaults to what the file name implies; a file name
// that implies none (a raw file) needs -format raw. -member checks that an
// archive holds the named files. -into adds the artifact to a release of a
// manifest file, creating the release if needed. Given -dist or -fetch,
// verify checks the size and digests of every artifact: relative URLs
// against the files below the -dist directory, absolute http and https
// URLs by downloading them with -fetch. An artifact neither flag covers
// is an error, so a pass covers the whole manifest. Every output file is
// replaced atomically.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/djylb/selfupdate"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "selfupdate:", err) // exiting with status 1 anyway
		os.Exit(1)
	}
}

const usage = "usage: selfupdate keygen|pubkey|artifact|sign|verify|sign-file|verify-file [flags]"

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmds := map[string]func([]string, io.Reader, io.Writer) error{
		"keygen":      keygen,
		"pubkey":      pubkey,
		"artifact":    artifact,
		"sign":        signCmd,
		"verify":      verify,
		"sign-file":   signFile,
		"verify-file": verifyFile,
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		return errors.New(usage)
	}
	return cmd(args[1:], stdin, stdout)
}

func keygen(args []string, _ io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "file to write the private key to (required, must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	pub, priv, err := selfupdate.GenerateKey()
	if err != nil {
		return err
	}
	if err := writeNew(*out, []byte(selfupdate.FormatPrivateKey(priv)+"\n"), 0o600); err != nil {
		return err
	}
	return printPublic(stdout, pub)
}

func printPublic(w io.Writer, pub ed25519.PublicKey) error {
	_, err := fmt.Fprintf(w, "public key: %s\nkey id:     %s\n", selfupdate.FormatPublicKey(pub), selfupdate.KeyID(pub))
	return err
}

func pubkey(args []string, _ io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	key := fs.String("key", "", "private key file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := readPrivate(*key)
	if err != nil {
		return err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return printPublic(stdout, pub)
}

func artifact(args []string, _ io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("artifact", flag.ContinueOnError)
	var a selfupdate.Artifact
	var format selfupdate.Format
	var members stringList
	fs.StringVar(&a.Name, "name", "", "logical artifact name (required)")
	fs.StringVar(&a.OS, "os", "", "GOOS, empty for any")
	fs.StringVar(&a.Arch, "arch", "", "GOARCH, empty for any")
	fs.StringVar(&a.URL, "url", "", "artifact URL, may be relative to the manifest; default the file name")
	fs.TextVar(&format, "format", selfupdate.FormatUnknown, "raw, gz, tar, tar.gz or zip; default implied by the file name")
	fs.Var(&members, "member", "file the archive must hold (repeatable)")
	into := fs.String("into", "", "manifest JSON file to add the artifact to")
	version := fs.String("version", "", "release version, with -into")
	channel := fs.String("channel", "", "release channel of a new release, with -into")
	notes := fs.String("notes", "", "release notes of a new release, with -into")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || a.Name == "" {
		return errors.New("artifact: expects -name and one file")
	}
	file := fs.Arg(0)
	implied := selfupdate.FormatOf(file)
	switch {
	case format == selfupdate.FormatUnknown && implied == selfupdate.FormatUnknown:
		return fmt.Errorf("artifact: the name %s implies no format: give -format (raw for a plain file)", file)
	case format == selfupdate.FormatUnknown:
		format = implied
	case implied != selfupdate.FormatUnknown && implied != format:
		return fmt.Errorf("artifact: -format %v, but the name %s implies %v", format, file, implied)
	}
	a.Format = format
	if a.URL == "" {
		a.URL = filepath.Base(file)
	}
	size, d, err := selfupdate.DigestFile(file)
	if err != nil {
		return err
	}
	a.Size = size
	a.SHA256 = hex.EncodeToString(d.SHA256[:])
	a.SHA512 = hex.EncodeToString(d.SHA512[:])
	if err := a.Check(size, d); err != nil {
		return err
	}
	if err := checkMembers(file, a, members); err != nil {
		return err
	}
	if *into != "" {
		return addToManifest(*into, *version, *channel, *notes, a)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(a)
}

// checkMembers extracts the named members into a temporary directory.
func checkMembers(file string, a selfupdate.Artifact, names []string) error {
	if len(names) == 0 {
		return nil
	}
	dir, err := os.MkdirTemp("", "selfupdate-members-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	members := make([]selfupdate.Member, len(names))
	for i, n := range names {
		members[i] = selfupdate.Member{Name: n, Path: filepath.Join(dir, fmt.Sprint(i))}
	}
	if err := selfupdate.Extract(context.Background(), f, a.Size, a.Format, members, selfupdate.ExtractOptions{}); err != nil {
		return fmt.Errorf("artifact: %w", err)
	}
	return nil
}

func addToManifest(path, version, channel, notes string, a selfupdate.Artifact) error {
	if version == "" {
		return errors.New("artifact: -into needs -version")
	}
	if _, err := selfupdate.ParseVersion(version); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m, err := selfupdate.DecodeManifest(data)
	if err != nil {
		return err
	}
	var r *selfupdate.Release
	for i := range m.Releases {
		if c, err := selfupdate.CompareVersions(m.Releases[i].Version, version); err == nil && c == 0 {
			r = &m.Releases[i]
		}
	}
	if r == nil {
		m.Releases = append(m.Releases, selfupdate.Release{Version: version, Channel: channel, Notes: notes})
		r = &m.Releases[len(m.Releases)-1]
	} else if channel != "" && channel != r.Channel {
		return fmt.Errorf("artifact: release %s is in channel %q", r.Version, r.Channel)
	}
	overlaps := func(x, y string) bool { return x == "" || y == "" || x == y }
	for _, o := range r.Artifacts {
		if o.Name == a.Name && overlaps(o.OS, a.OS) && overlaps(o.Arch, a.Arch) {
			return fmt.Errorf("artifact: release %s already has an artifact %s for %s/%s", r.Version, o.Name, o.OS, o.Arch)
		}
	}
	r.Artifacts = append(r.Artifacts, a)
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(out, '\n'), 0o644)
}

func readPrivate(file string) (ed25519.PrivateKey, error) {
	if file == "" {
		return nil, errors.New("-key is required")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	priv, err := selfupdate.ParsePrivateKey(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return priv, nil
}

func readPrivates(files []string) ([]ed25519.PrivateKey, error) {
	if len(files) == 0 {
		return nil, errors.New("at least one -key is required")
	}
	privs := make([]ed25519.PrivateKey, 0, len(files))
	for _, k := range files {
		priv, err := readPrivate(k)
		if err != nil {
			return nil, err
		}
		privs = append(privs, priv)
	}
	return privs, nil
}

func readTrust(pubs []string) (selfupdate.Trust, error) {
	var t selfupdate.Trust
	for _, p := range pubs {
		pub, err := selfupdate.ParsePublicKey(p)
		if err != nil {
			return t, err
		}
		t.Keys = append(t.Keys, selfupdate.TrustedKey{Public: pub})
	}
	return t, nil
}

func signCmd(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	var keys stringList
	fs.Var(&keys, "key", "private key file (repeatable)")
	expires := fs.Duration("expires", 30*24*time.Hour, "validity from now")
	in := fs.String("in", "-", "manifest JSON")
	out := fs.String("out", "-", "signed manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	privs, err := readPrivates(keys)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if *expires <= 0 {
		return errors.New("sign: -expires must be positive")
	}
	data, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	m, err := selfupdate.DecodeManifest(data)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	m.Published, m.Expires = now, now.Add(*expires)
	signed, err := selfupdate.SignManifest(m, privs...)
	if err != nil {
		return err
	}
	return writeOutput(*out, stdout, append(signed, '\n'))
}

func verify(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var pubs stringList
	fs.Var(&pubs, "pub", "trusted public key (repeatable)")
	in := fs.String("in", "-", "signed manifest")
	dist := fs.String("dist", "", "directory to check the artifacts with relative URLs against")
	fetch := fs.Bool("fetch", false, "download and check the artifacts with absolute http(s) URLs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	t, err := readTrust(pubs)
	if err != nil {
		return err
	}
	data, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	opened, err := selfupdate.OpenManifest(data, t, time.Now())
	if err != nil {
		return err
	}
	if *dist != "" || *fetch {
		if err := checkArtifacts(context.Background(), *dist, *fetch, opened.Manifest); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(stdout, "signed by: %s\n", strings.Join(opened.KeyIDs, ", ")); err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(opened.Manifest)
}

// checkArtifacts checks every artifact of m with [selfupdate.Download]:
// one with a relative URL against its file below dir, one with an
// absolute URL by fetching it if fetch is set. It refuses to start if
// any artifact is covered by neither, so a check that passes covers the
// whole manifest.
func checkArtifacts(ctx context.Context, dir string, fetch bool, m *selfupdate.Manifest) error {
	type job struct {
		version string
		a       selfupdate.Artifact
		src     selfupdate.Source
	}
	var (
		jobs      []job
		unchecked []string
		local     = &selfupdate.DirSource{Dir: dir}
		remote    = &selfupdate.HTTPSource{}
	)
	for _, r := range m.Releases {
		for _, a := range r.Artifacts {
			u, err := url.Parse(a.URL)
			absolute := err == nil && (u.Scheme != "" || u.Host != "")
			switch {
			case absolute && fetch:
				jobs = append(jobs, job{r.Version, a, remote})
			case !absolute && dir != "":
				jobs = append(jobs, job{r.Version, a, local})
			case absolute:
				unchecked = append(unchecked, r.Version+" "+a.URL+" (needs -fetch)")
			default:
				unchecked = append(unchecked, r.Version+" "+a.URL+" (needs -dist)")
			}
		}
	}
	if len(unchecked) > 0 {
		return fmt.Errorf("verify: unchecked artifacts:\n  %s", strings.Join(unchecked, "\n  "))
	}
	tmp, err := os.MkdirTemp("", "selfupdate-verify-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for i, j := range jobs {
		f, err := selfupdate.Download(ctx, j.src, j.a, filepath.Join(tmp, fmt.Sprint(i)), nil)
		if err != nil {
			return fmt.Errorf("verify: release %s, %s: %w", j.version, j.a.URL, err)
		}
		_ = f.Close()
		_ = os.Remove(f.Name())
	}
	return nil
}

func signFile(args []string, _ io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign-file", flag.ContinueOnError)
	var keys stringList
	fs.Var(&keys, "key", "private key file (repeatable)")
	out := fs.String("out", "-", "signature file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("sign-file: expects one file")
	}
	privs, err := readPrivates(keys)
	if err != nil {
		return fmt.Errorf("sign-file: %w", err)
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sigs, err := selfupdate.SignArtifact(f, privs...)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(sigs, "", "  ")
	if err != nil {
		return err
	}
	return writeOutput(*out, stdout, append(data, '\n'))
}

func verifyFile(args []string, _ io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify-file", flag.ContinueOnError)
	var pubs stringList
	fs.Var(&pubs, "pub", "trusted public key (repeatable)")
	sigFile := fs.String("sig", "", "signature file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *sigFile == "" {
		return errors.New("verify-file: expects -sig and one file")
	}
	t, err := readTrust(pubs)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*sigFile)
	if err != nil {
		return err
	}
	var sigs []selfupdate.Signature
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sigs); err != nil {
		return fmt.Errorf("%s: %w", *sigFile, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: trailing data", *sigFile)
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	ids, err := selfupdate.VerifyArtifact(f, sigs, t, time.Now())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "signed by: %s\n", strings.Join(ids, ", "))
	return err
}

func readInput(name string, stdin io.Reader) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(name)
}

func writeOutput(name string, stdout io.Writer, data []byte) error {
	if name == "-" {
		_, err := stdout.Write(data)
		return err
	}
	return writeAtomic(name, data, 0o644)
}

// writeNew writes data to the file name, which must not exist, so that
// the name either holds all of data or does not exist.
func writeNew(name string, data []byte, mode os.FileMode) (err error) {
	tmp, err := tempFile(name, data, mode)
	if err != nil {
		return err
	}
	// A link fails if name exists, unlike a rename, and leaves tmp to
	// delete either way.
	if err = os.Link(tmp, name); err != nil && !errors.Is(err, fs.ErrExist) {
		err = fmt.Errorf("%s: the file system must support hard links, so the file appears complete or not at all: %w", name, err)
	}
	return errors.Join(err, os.Remove(tmp))
}

// writeAtomic replaces the file at name with data, so a reader never sees
// a partial file.
func writeAtomic(name string, data []byte, mode os.FileMode) error {
	tmp, err := tempFile(name, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		return errors.Join(err, os.Remove(tmp))
	}
	return nil
}

// tempFile writes data, synced, to a new file next to name and returns
// its path.
func tempFile(name string, data []byte, mode os.FileMode) (_ string, err error) {
	f, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+".tmp-*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err = errors.Join(err, f.Chmod(mode), f.Sync(), f.Close()); err != nil {
		return "", errors.Join(err, os.Remove(f.Name()))
	}
	return f.Name(), nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
