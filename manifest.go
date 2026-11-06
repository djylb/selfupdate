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
	"slices"
	"strings"
	"time"
)

// Errors returned when opening a manifest.
var (
	ErrMalformedManifest   = errors.New("selfupdate: malformed manifest")
	ErrUnsupportedManifest = errors.New("selfupdate: manifest needs capabilities this client lacks")
	ErrExpiredManifest     = errors.New("selfupdate: manifest expired")
	ErrNoExpiry            = errors.New("selfupdate: manifest has no expiry")
	ErrDigestMismatch      = errors.New("selfupdate: digest mismatch")
)

// ManifestFormat is the only manifest format this package reads. An
// incompatible format gets a new number and a new file name, and shares the
// serial counter.
const ManifestFormat = 1

// maxSerial keeps serials exact in tools that store numbers as doubles.
const maxSerial = 1<<53 - 1

// Manifest describes the releases of one product and the upgrade rules
// between them. Publishers sign it with [SignManifest]; clients open it with
// [OpenManifest] and choose a release with [Resolve].
type Manifest struct {
	// Published is when the manifest was produced.
	Published time.Time `json:"published"`
	// Expires bounds how long the manifest is accepted. It is mandatory:
	// it limits how long an attacker can replay an old signed manifest to
	// hold clients back on a vulnerable version.
	Expires time.Time `json:"expires"`
	// Facts declares the facts rules may ask about.
	Facts map[string]Fact `json:"facts,omitempty"`
	// Product names what the manifest is for. Clients check it, so that a
	// manifest signed for one product is never applied to another one
	// sharing the same keys. Put environments in it too, as "app-staging".
	Product string `json:"product"`
	// Requires lists capabilities a client must have to use the manifest at
	// all.
	Requires []string `json:"requires,omitempty"`
	// Baseline holds the default gates, mandatory so that a publisher decides
	// them; an empty list says every forward edge is open by default. An
	// allow rule cancels a baseline gate.
	Baseline []Rule `json:"baseline"`
	// Releases lists the available releases in any order.
	Releases []Release `json:"releases"`
	// Rules lists the exceptions. The order has no meaning.
	Rules []Rule `json:"rules,omitempty"`
	// Format is [ManifestFormat].
	Format int `json:"format"`
	// Serial grows with every manifest of the product, also across formats
	// and maintenance lines; clients refuse lower ones. 1 to 2^53-1.
	Serial uint64 `json:"serial"`
}

// Release is one version of a product.
type Release struct {
	// Rollout limits who sees the release; nil means everyone.
	Rollout *Rollout `json:"rollout,omitempty"`
	// Version is a semantic version.
	Version string `json:"version"`
	// Notes is free text for humans.
	Notes string `json:"notes,omitempty"`
	// Channels lists the channels the release is in. Empty means the default
	// channel, visible to all; otherwise a client needs the grant
	// "channel:<name>" for one of them.
	Channels []string `json:"channels,omitempty"`
	// Labels are open tags for the to.label fact.
	Labels []string `json:"labels,omitempty"`
	// Requires lists capabilities a source version must have for this
	// release to exist for it.
	Requires []string `json:"requires,omitempty"`
	// Provides is the complete set of capabilities of this release, not
	// inherited from any other, exported from the build (see
	// [LibraryCapabilities]). Empty means unknown.
	Provides []string `json:"provides,omitempty"`
	// Attrs is passed through to the caller.
	Attrs json.RawMessage `json:"attrs,omitempty"`
	// Artifacts lists the downloadable files of the release. For one name
	// and platform the first usable one is taken, so a new format can be
	// listed before an old one.
	Artifacts []Artifact `json:"artifacts"`
}

// Rollout is a gradual release.
type Rollout struct {
	// Percent is the share of installations that see the release.
	Percent int `json:"percent"`
	// Paused hides the release from everyone; no grant lifts it.
	Paused bool `json:"paused,omitempty"`
}

// Action says how an artifact is installed.
type Action struct {
	// Kind names an action of [Updater].Actions, or "replace".
	Kind string `json:"kind"`
	// Params is data for the action; it is never interpreted here.
	Params json.RawMessage `json:"params,omitempty"`
}

// clone copies what a caller could change through a [Candidate].
func (a *Artifact) clone() Artifact {
	c := *a
	c.Requires = slices.Clone(a.Requires)
	if a.Action != nil {
		act := *a.Action
		act.Params = slices.Clone(a.Action.Params)
		c.Action = &act
	}
	return c
}

// Artifact is one downloadable file of a release.
type Artifact struct {
	// Action says how to install the artifact; nil means replace.
	Action *Action `json:"action,omitempty"`
	// Name is the logical name the client asks for, such as the program
	// name or the name of a data file.
	Name string `json:"name"`
	// OS and Arch use GOOS and GOARCH values. Empty matches every platform,
	// which suits data files.
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
	// URL locates the file; the [Source] interprets it. [HTTPSource] resolves
	// a relative URL against the manifest URL, [DirSource] takes a path
	// below its directory.
	URL string `json:"url"`
	// SHA256 and SHA512 are hex digests of the file. At least one is
	// required; when both are present both are checked.
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
	// Requires lists capabilities needed to use this artifact.
	Requires []string `json:"requires,omitempty"`
	// rawFormat keeps a format name this package does not know, so that a
	// future version providing it can still be judged.
	rawFormat string
	// Size is the exact size of the file in bytes.
	Size int64 `json:"size"`
	// Format is how the file is packed.
	Format Format `json:"format"`
}

// Digest returns the strongest digest the artifact pins, as "sha512:<hex>" or
// "sha256:<hex>". It identifies the content in failure records.
func (a *Artifact) Digest() string {
	if a.SHA512 != "" {
		return "sha512:" + a.SHA512
	}
	if a.SHA256 != "" {
		return "sha256:" + a.SHA256
	}
	return ""
}

// needs returns the capabilities using the artifact takes, its explicit ones
// and those implied by its format, digests and action.
func (a *Artifact) needs() []string {
	format := a.rawFormat
	if format == "" {
		format = a.Format.String()
	}
	out := append(slices.Clone(a.Requires), "format:"+format)
	if a.SHA256 != "" {
		out = append(out, "digest:sha256")
	}
	if a.SHA512 != "" {
		out = append(out, "digest:sha512")
	}
	kind := actionReplace
	if a.Action != nil && a.Action.Kind != "" {
		kind = a.Action.Kind
	}
	return append(out, "action:"+kind)
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
// content open. Only the digests the artifact lists are compared.
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
	case !a.Format.valid() && a.rawFormat == "":
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
	// Hash is the SHA-256 of the signed payload.
	Hash [sha256.Size]byte
}

// OpenManifest checks the signatures on data against t and the manifest's
// validity period at time now, and returns the decoded manifest. Nothing in
// the payload is looked at before the signatures pass.
//
// Decoding is lenient, so that new manifests reach old clients: unknown fields
// are ignored (the signature covers the exact bytes), and a damaged entry
// affects itself only. An artifact or release that cannot be read does not
// exist, and a rule that cannot be read counts as unknown. Duplicate keys and
// missing mandatory fields stay fatal, because they are ambiguous.
func OpenManifest(data []byte, t Trust, now time.Time) (*Opened, error) {
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	if err := atEOF(dec); err != nil {
		return nil, err
	}
	ids, err := t.verify(manifestContext, env.Payload, env.Signatures, now)
	if err != nil {
		return nil, err
	}
	m, err := decodeLenient(env.Payload)
	if err != nil {
		return nil, err
	}
	if err := m.validateCore(); err != nil {
		return nil, err
	}
	if !now.Before(m.Expires) && !t.InsecureAcceptExpired {
		return nil, fmt.Errorf("%w at %s", ErrExpiredManifest, m.Expires.Format(time.RFC3339))
	}
	return &Opened{Manifest: m, KeyIDs: ids, Hash: sha256.Sum256(env.Payload)}, nil
}

// decodeLenient decodes a payload the way clients read it; see [OpenManifest].
func decodeLenient(payload []byte) (*Manifest, error) {
	if err := checkDuplicateKeys(payload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	var w struct {
		Published time.Time                  `json:"published"`
		Expires   time.Time                  `json:"expires"`
		Facts     map[string]json.RawMessage `json:"facts"`
		Baseline  *[]json.RawMessage         `json:"baseline"`
		Product   string                     `json:"product"`
		Requires  []string                   `json:"requires"`
		Releases  []json.RawMessage          `json:"releases"`
		Rules     []json.RawMessage          `json:"rules"`
		Format    int                        `json:"format"`
		Serial    uint64                     `json:"serial"`
	}
	if err := json.Unmarshal(payload, &w); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	m := &Manifest{
		Published: w.Published, Expires: w.Expires, Product: w.Product,
		Requires: w.Requires, Format: w.Format, Serial: w.Serial,
	}
	for name, raw := range w.Facts {
		var f Fact
		if json.Unmarshal(raw, &f) == nil {
			if m.Facts == nil {
				m.Facts = map[string]Fact{}
			}
			m.Facts[name] = f
		}
	}
	if w.Baseline != nil {
		m.Baseline = decodeRules(*w.Baseline)
	}
	m.Rules = decodeRules(w.Rules)
	for _, raw := range w.Releases {
		if r, ok := decodeRelease(raw); ok {
			m.Releases = append(m.Releases, r)
		}
	}
	return m, nil
}

func decodeRelease(raw json.RawMessage) (Release, bool) {
	var w struct {
		Release
		Artifacts []json.RawMessage `json:"artifacts"`
	}
	if json.Unmarshal(raw, &w) != nil {
		return Release{}, false
	}
	if _, err := ParseVersion(w.Version); err != nil {
		return Release{}, false
	}
	r := w.Release
	r.Artifacts = nil
	for _, ra := range w.Artifacts {
		var a struct {
			Artifact
			Format string `json:"format"`
		}
		if json.Unmarshal(ra, &a) != nil {
			continue
		}
		art := a.Artifact
		if art.Format.UnmarshalText([]byte(a.Format)) != nil {
			art.Format, art.rawFormat = FormatUnknown, a.Format
		}
		if art.validate() == nil {
			r.Artifacts = append(r.Artifacts, art)
		}
	}
	return r, true
}

// decodeRules reads rules; one that cannot be read keeps what can be read of
// it and counts as unknown.
func decodeRules(raws []json.RawMessage) []Rule {
	out := make([]Rule, 0, len(raws))
	for _, raw := range raws {
		var r Rule
		if json.Unmarshal(raw, &r) != nil {
			r = Rule{damaged: true}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			for name, p := range map[string]any{
				"id": &r.ID, "from": &r.From, "to": &r.To, "unlock": &r.Unlock, "if_unknown": &r.IfUnknown,
				"message": &r.Message, "url": &r.URL, "reason": &r.Reason, "effect": &r.Effect,
			} {
				if v, ok := fields[name]; ok {
					_ = json.Unmarshal(v, p)
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// DecodeManifest decodes the JSON form of a [Manifest] strictly, for
// publishers: unknown fields, duplicate keys (compared case-insensitively, as
// decoding matches them) and trailing data are rejected, so a misspelt field
// cannot silently loosen or tighten a rule. It does not validate the manifest.
// Clients are lenient instead; see [OpenManifest].
func DecodeManifest(payload []byte) (*Manifest, error) {
	if err := checkDuplicateKeys(payload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	m := new(Manifest)
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	if err := atEOF(dec); err != nil {
		return nil, err
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

// atEOF checks that nothing but white space follows the decoded value.
func atEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrMalformedManifest)
	}
	return nil
}

// validateCore checks what every reader must agree on.
func (m *Manifest) validateCore() error {
	switch {
	case m.Format == 0:
		return fmt.Errorf("%w: no format", ErrMalformedManifest)
	case m.Format != ManifestFormat:
		return fmt.Errorf("%w: format %d", ErrUnsupportedManifest, m.Format)
	case m.Serial == 0 || m.Serial > maxSerial:
		return fmt.Errorf("%w: serial %d out of range", ErrMalformedManifest, m.Serial)
	case m.Product == "":
		return fmt.Errorf("%w: no product", ErrMalformedManifest)
	case m.Expires.IsZero():
		return ErrNoExpiry
	case m.Published.IsZero():
		return fmt.Errorf("%w: no publication time", ErrMalformedManifest)
	case !m.Published.Before(m.Expires):
		return fmt.Errorf("%w: published after it expires", ErrMalformedManifest)
	case m.Baseline == nil:
		return fmt.Errorf("%w: no baseline", ErrMalformedManifest)
	}
	versions := make([]Version, 0, len(m.Releases))
	for i := range m.Releases {
		r := &m.Releases[i]
		v, err := ParseVersion(r.Version)
		if err != nil {
			return fmt.Errorf("%w: release %q: %w", ErrMalformedManifest, r.Version, err)
		}
		for _, o := range versions {
			if v.Compare(o) == 0 {
				return fmt.Errorf("%w: version %s listed twice", ErrMalformedManifest, r.Version)
			}
		}
		versions = append(versions, v)
	}
	ids := map[string]bool{}
	for _, list := range [][]Rule{m.Baseline, m.Rules} {
		for i := range list {
			id := list[i].ID
			if id != "" && ids[id] {
				return fmt.Errorf("%w: rule id %q used twice", ErrMalformedManifest, id)
			}
			ids[id] = true
		}
	}
	return nil
}

// validate is the strict check of a publisher: nothing may be unknown.
func (m *Manifest) validate() error {
	if err := m.validateCore(); err != nil {
		return err
	}
	for i := range m.Releases {
		r := &m.Releases[i]
		for j := range r.Artifacts {
			if err := r.Artifacts[j].validate(); err != nil {
				return err
			}
		}
		if r.Rollout != nil && (r.Rollout.Percent < 0 || r.Rollout.Percent > 100) {
			return fmt.Errorf("%w: release %s: rollout percent %d", ErrMalformedManifest, r.Version, r.Rollout.Percent)
		}
	}
	for name := range m.Facts {
		if isBuiltinFact(name) || strings.HasPrefix(name, "edge.") || strings.HasPrefix(name, "to.") || strings.HasPrefix(name, "from.") {
			return fmt.Errorf("%w: fact name %q is reserved", ErrMalformedManifest, name)
		}
	}
	for _, list := range [][]Rule{m.Baseline, m.Rules} {
		for i := range list {
			r := &list[i]
			if r.ID == "" {
				return fmt.Errorf("%w: rule without id", ErrMalformedManifest)
			}
			if err := m.checkRule(r, false); err != nil {
				return fmt.Errorf("%w: rule %s: %w", ErrMalformedManifest, r.ID, err)
			}
		}
	}
	return nil
}
