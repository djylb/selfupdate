package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Errors returned when opening a manifest.
var (
	ErrMalformedManifest = errors.New("selfupdate: malformed manifest")
	ErrExpiredManifest   = errors.New("selfupdate: manifest expired")
	ErrNoExpiry          = errors.New("selfupdate: manifest has no expiry")
	ErrDigestMismatch    = errors.New("selfupdate: digest mismatch")
)

// Manifest describes the releases of one product. Publishers sign it with
// [SignManifest]; clients open it with [OpenManifest].
type Manifest struct {
	// Published is when the manifest was produced.
	Published time.Time `json:"published"`
	// Expires bounds how long the manifest is accepted. It is mandatory:
	// it limits how long an attacker can replay an old signed manifest to
	// hold clients back on a vulnerable version.
	Expires time.Time `json:"expires"`
	// Product names what the manifest is for. Clients check it, so that a
	// manifest signed for one product is never applied to another one
	// sharing the same keys.
	Product string `json:"product"`
	// Releases lists the available releases in any order.
	Releases []Release `json:"releases"`
}

// Release is one version of a product.
type Release struct {
	// Version is a semantic version.
	Version string `json:"version"`
	// Channel names the release channel, such as "beta". Empty means the
	// default (stable) channel.
	Channel string `json:"channel,omitempty"`
	// Notes is free text for humans.
	Notes string `json:"notes,omitempty"`
	// Artifacts lists the downloadable files of the release.
	Artifacts []Artifact `json:"artifacts"`
}

// Artifact is one downloadable file of a release.
type Artifact struct {
	// Name is the logical name the client asks for, such as the program
	// name or the name of a data file.
	Name string `json:"name"`
	// OS and Arch use GOOS and GOARCH values. Empty matches every platform,
	// which suits data files.
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
	// URL locates the file. A relative URL is resolved against the URL the
	// manifest was fetched from.
	URL string `json:"url"`
	// SHA256 and SHA512 are hex digests of the file. At least one is
	// required; when both are present both are checked.
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
	// Size is the exact size of the file in bytes.
	Size int64 `json:"size"`
	// Format is how the file is packed.
	Format Format `json:"format"`
}

// Digests holds the digests of a file.
type Digests struct {
	SHA256 [sha256.Size]byte
	SHA512 [sha512.Size]byte
}

// DigestsOf returns the digests of data.
func DigestsOf(data []byte) Digests {
	return Digests{SHA256: sha256.Sum256(data), SHA512: sha512.Sum512(data)}
}

// Check reports whether size and d match the artifact. It also rejects an
// artifact that pins no digest or no size, so a manifest cannot leave the
// content open.
func (a *Artifact) Check(size int64, d Digests) error {
	if err := a.validate(); err != nil {
		return err
	}
	if size != a.Size {
		return fmt.Errorf("%w: size %d, want %d", ErrDigestMismatch, size, a.Size)
	}
	if a.SHA256 != "" && a.SHA256 != hex.EncodeToString(d.SHA256[:]) {
		return fmt.Errorf("%w: sha256", ErrDigestMismatch)
	}
	if a.SHA512 != "" && a.SHA512 != hex.EncodeToString(d.SHA512[:]) {
		return fmt.Errorf("%w: sha512", ErrDigestMismatch)
	}
	return nil
}

func (a *Artifact) validate() error {
	switch {
	case a.Name == "", a.URL == "":
		return fmt.Errorf("%w: artifact without name or url", ErrMalformedManifest)
	case a.Size <= 0:
		return fmt.Errorf("%w: artifact %s without size", ErrMalformedManifest, a.Name)
	case a.SHA256 == "" && a.SHA512 == "":
		return fmt.Errorf("%w: artifact %s without digest", ErrMalformedManifest, a.Name)
	case a.SHA256 != "" && !isHex(a.SHA256, sha256.Size):
		return fmt.Errorf("%w: artifact %s: bad sha256", ErrMalformedManifest, a.Name)
	case a.SHA512 != "" && !isHex(a.SHA512, sha512.Size):
		return fmt.Errorf("%w: artifact %s: bad sha512", ErrMalformedManifest, a.Name)
	case !a.Format.valid():
		return fmt.Errorf("%w: artifact %s: unknown format", ErrMalformedManifest, a.Name)
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != 2*n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Artifact returns the artifact of r with the given name for goos and
// goarch. An artifact without OS or Arch matches any value.
func (r *Release) Artifact(name, goos, goarch string) (Artifact, bool) {
	for _, a := range r.Artifacts {
		if a.Name == name && (a.OS == "" || a.OS == goos) && (a.Arch == "" || a.Arch == goarch) {
			return a, true
		}
	}
	return Artifact{}, false
}

// envelope is the signed wire form of a manifest. The payload is signed as
// the exact bytes it carries, so no canonical JSON form is needed.
type envelope struct {
	Payload    []byte      `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

// SignManifest validates m, encodes it and signs it with every key. The
// result is the document to publish.
func SignManifest(m *Manifest, keys ...ed25519.PrivateKey) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sigs, err := sign(manifestContext, payload, keys)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(envelope{Payload: payload, Signatures: sigs}, "", "  ")
}

// UnsignedManifest encodes m without signatures, for clients that set
// [Trust.InsecureSkipSignature].
func UnsignedManifest(m *Manifest) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(envelope{Payload: payload, Signatures: []Signature{}}, "", "  ")
}

// Opened is a manifest whose signatures and freshness were checked.
type Opened struct {
	// Manifest is the decoded manifest.
	Manifest *Manifest
	// KeyIDs lists the trusted keys that signed it; it is empty only
	// when signatures were skipped.
	KeyIDs []string
}

// OpenManifest checks the signatures on data against t and the manifest's
// validity period at time now, and returns the decoded manifest. Nothing in
// the payload is looked at before the signatures pass.
func OpenManifest(data []byte, t Trust, now time.Time) (*Opened, error) {
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformedManifest)
	}
	ids, err := t.verify(manifestContext, env.Payload, env.Signatures, now)
	if err != nil {
		return nil, err
	}
	m, err := decodePayload(env.Payload)
	if err != nil {
		return nil, err
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	if !now.Before(m.Expires) {
		return nil, fmt.Errorf("%w at %s", ErrExpiredManifest, m.Expires.Format(time.RFC3339))
	}
	return &Opened{Manifest: m, KeyIDs: ids}, nil
}

// decodePayload decodes a signed payload strictly, so that every client,
// in any language, reads the same signed bytes the same way: unknown
// fields, duplicate keys (compared case-insensitively, as decoding
// matches them) and trailing data are rejected.
func decodePayload(payload []byte) (*Manifest, error) {
	if err := checkDuplicateKeys(payload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	m := new(Manifest)
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformedManifest)
	}
	return m, nil
}

func checkDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		keys   map[string]bool
		object bool
		key    bool // the next string token in an object is a key
	}
	var stack []frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		top := len(stack) - 1
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				stack = append(stack, frame{keys: map[string]bool{}, object: true, key: true})
			case '[':
				stack = append(stack, frame{})
			default:
				stack = stack[:top]
				if top > 0 && stack[top-1].object {
					stack[top-1].key = true
				}
			}
			continue
		}
		if top < 0 || !stack[top].object {
			continue
		}
		if stack[top].key {
			key, _ := tok.(string)
			k := strings.ToLower(key)
			if stack[top].keys[k] {
				return fmt.Errorf("duplicate key %q", tok)
			}
			stack[top].keys[k] = true
			stack[top].key = false
		} else {
			stack[top].key = true
		}
	}
}

func (m *Manifest) validate() error {
	if m.Product == "" {
		return fmt.Errorf("%w: no product", ErrMalformedManifest)
	}
	if m.Expires.IsZero() {
		return ErrNoExpiry
	}
	for i := range m.Releases {
		r := &m.Releases[i]
		if _, err := ParseVersion(r.Version); err != nil {
			return fmt.Errorf("%w: release %q: %w", ErrMalformedManifest, r.Version, err)
		}
		for j := range r.Artifacts {
			if err := r.Artifacts[j].validate(); err != nil {
				return err
			}
		}
	}
	return nil
}
