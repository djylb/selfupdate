// Command selfupdate creates keys and signed manifests for the selfupdate
// package.
//
// Usage:
//
//	selfupdate keygen -out release.key
//	selfupdate artifact -name app -os linux -arch amd64 -format tar.gz -url app_linux_amd64.tar.gz dist/app_linux_amd64.tar.gz
//	selfupdate sign -key release.key -expires 720h -in manifest.json -out manifest.signed.json
//	selfupdate verify -pub ed25519:... -in manifest.signed.json
//
// The manifest given to sign is the JSON form of selfupdate.Manifest; a
// zero "published" is set to now and a zero "expires" to now plus -expires.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/djylb/selfupdate"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "selfupdate:", err)
		os.Exit(1)
	}
}

const usage = "usage: selfupdate keygen|artifact|sign|verify [flags]"

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout)
	case "artifact":
		return artifact(args[1:], stdout)
	case "sign":
		return signCmd(args[1:], stdin, stdout)
	case "verify":
		return verify(args[1:], stdin, stdout)
	}
	return errors.New(usage)
}

func keygen(args []string, stdout io.Writer) error {
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
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, selfupdate.FormatPrivateKey(priv))
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "public key: %s\nkey id:     %s\n", selfupdate.FormatPublicKey(pub), selfupdate.KeyID(pub))
	return err
}

func artifact(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("artifact", flag.ContinueOnError)
	var a selfupdate.Artifact
	fs.StringVar(&a.Name, "name", "", "logical artifact name (required)")
	fs.StringVar(&a.OS, "os", "", "GOOS, empty for any")
	fs.StringVar(&a.Arch, "arch", "", "GOARCH, empty for any")
	fs.StringVar(&a.URL, "url", "", "artifact URL, may be relative to the manifest (required)")
	fs.TextVar(&a.Format, "format", selfupdate.FormatRaw, "raw, gz, tar, tar.gz or zip")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("artifact: expects one file")
	}
	size, d, err := selfupdate.DigestFile(fs.Arg(0))
	if err != nil {
		return err
	}
	a.Size = size
	a.SHA256 = hex.EncodeToString(d.SHA256[:])
	a.SHA512 = hex.EncodeToString(d.SHA512[:])
	if err := a.Check(size, d); err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(a)
}

func signCmd(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	var keys stringList
	fs.Var(&keys, "key", "private key file (repeatable)")
	expires := fs.Duration("expires", 30*24*time.Hour, "validity when the manifest sets no expiry")
	in := fs.String("in", "-", "manifest JSON")
	out := fs.String("out", "-", "signed manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("sign: at least one -key is required")
	}
	privs := make([]ed25519.PrivateKey, 0, len(keys))
	for _, k := range keys {
		b, err := os.ReadFile(k)
		if err != nil {
			return err
		}
		priv, err := selfupdate.ParsePrivateKey(string(b))
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		privs = append(privs, priv)
	}
	data, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	var m selfupdate.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if m.Published.IsZero() {
		m.Published = now
	}
	if m.Expires.IsZero() {
		m.Expires = now.Add(*expires)
	}
	signed, err := selfupdate.SignManifest(&m, privs...)
	if err != nil {
		return err
	}
	signed = append(signed, '\n')
	if *out == "-" {
		_, err = stdout.Write(signed)
		return err
	}
	return os.WriteFile(*out, signed, 0o644)
}

func verify(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var pubs stringList
	fs.Var(&pubs, "pub", "trusted public key (repeatable)")
	in := fs.String("in", "-", "signed manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var t selfupdate.Trust
	for _, p := range pubs {
		pub, err := selfupdate.ParsePublicKey(p)
		if err != nil {
			return err
		}
		t.Keys = append(t.Keys, selfupdate.TrustedKey{Public: pub})
	}
	data, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	opened, err := selfupdate.OpenManifest(data, t, time.Now())
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "signed by: %s\n", strings.Join(opened.KeyIDs, ", ")); err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(opened.Manifest)
}

func readInput(name string, stdin io.Reader) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(name)
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
