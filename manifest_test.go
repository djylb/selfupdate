package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleManifest() *Manifest {
	return manifestOf("app", Release{Version: "1.2.0", Artifacts: []Artifact{
		artifactFor("app", "app.bin", FormatRaw, []byte("binary")),
	}})
}

func TestOpenManifest(t *testing.T) {
	k1, k2, other := newTestKey(t), newTestKey(t), newTestKey(t)
	signed := mustSign(t, sampleManifest(), k1)

	opened, err := OpenManifest(signed, k1.trust(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Manifest.Product != "app" || len(opened.KeyIDs) != 1 || opened.KeyIDs[0] != KeyID(k1.pub) {
		t.Fatalf("opened %+v", opened)
	}

	cases := map[string]struct {
		data  []byte
		trust Trust
		now   time.Time
		want  error
	}{
		"wrong key":     {signed, other.trust(), testNow, ErrUnsigned},
		"no keys":       {signed, Trust{}, testNow, ErrNoTrustedKeys},
		"expired":       {signed, k1.trust(), testNow.Add(25 * time.Hour), ErrExpiredManifest},
		"at expiry":     {signed, k1.trust(), testNow.Add(24 * time.Hour), ErrExpiredManifest},
		"retired key":   {signed, Trust{Keys: []TrustedKey{{Public: k1.pub, NotAfter: testNow.Add(-time.Second)}}}, testNow, ErrUnsigned},
		"threshold":     {signed, Trust{Keys: []TrustedKey{{Public: k1.pub}, {Public: k2.pub}}, Threshold: 2}, testNow, ErrUnsigned},
		"tampered":      {tamper(t, signed), k1.trust(), testNow, ErrUnsigned},
		"unsigned":      {mustUnsigned(t), k1.trust(), testNow, ErrUnsigned},
		"trailing data": {append(bytes.Clone(signed), "{}"...), k1.trust(), testNow, ErrMalformedManifest},
		"not json":      {[]byte("nope"), k1.trust(), testNow, ErrMalformedManifest},
	}
	for name, c := range cases {
		if _, err := OpenManifest(c.data, c.trust, c.now); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}

	// The same key signing twice does not count twice.
	twice := mustSign(t, sampleManifest(), k1, k1)
	if _, err := OpenManifest(twice, Trust{Keys: []TrustedKey{{Public: k1.pub}, {Public: k2.pub}}, Threshold: 2}, testNow); !errors.Is(err, ErrUnsigned) {
		t.Errorf("duplicate signature counted: %v", err)
	}
	// Rotation: signed by old and new, clients trusting either accept it.
	both := mustSign(t, sampleManifest(), k1, k2)
	for _, k := range []testKey{k1, k2} {
		if _, err := OpenManifest(both, k.trust(), testNow); err != nil {
			t.Errorf("rotation: %v", err)
		}
	}
	if _, err := OpenManifest(both, Trust{Keys: []TrustedKey{{Public: k1.pub}, {Public: k2.pub}}, Threshold: 2}, testNow); err != nil {
		t.Errorf("threshold 2: %v", err)
	}
	// Explicit opt-out accepts unsigned manifests but still checks expiry.
	insecure := Trust{InsecureSkipSignature: true}
	if _, err := OpenManifest(mustUnsigned(t), insecure, testNow); err != nil {
		t.Errorf("insecure: %v", err)
	}
	if _, err := OpenManifest(mustUnsigned(t), insecure, testNow.Add(48*time.Hour)); !errors.Is(err, ErrExpiredManifest) {
		t.Errorf("insecure expired: %v", err)
	}
}

func mustUnsigned(t *testing.T) []byte {
	t.Helper()
	data, err := UnsignedManifest(sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// tamper changes the version inside the signed payload.
func tamper(t *testing.T, signed []byte) []byte {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = bytes.Replace(env.Payload, []byte(`"1.2.0"`), []byte(`"9.9.9"`), 1)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSignManifestValidates(t *testing.T) {
	k := newTestKey(t)
	bad := []func(*Manifest){
		func(m *Manifest) { m.Expires = time.Time{} },
		func(m *Manifest) { m.Product = "" },
		func(m *Manifest) { m.Releases[0].Version = "latest" },
		func(m *Manifest) { m.Releases[0].Artifacts[0].SHA256, m.Releases[0].Artifacts[0].SHA512 = "", "" },
		func(m *Manifest) { m.Releases[0].Artifacts[0].Size = 0 },
		func(m *Manifest) { m.Releases[0].Artifacts[0].Format = FormatUnknown },
		func(m *Manifest) { m.Releases[0].Artifacts[0].SHA256 = strings.Repeat("A", 64) },
	}
	for i, f := range bad {
		m := sampleManifest()
		f(m)
		if _, err := SignManifest(m, k.priv); err == nil {
			t.Errorf("case %d: signed an invalid manifest", i)
		}
	}
	if _, err := SignManifest(sampleManifest()); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("no keys: %v", err)
	}
}

func TestKeyEncoding(t *testing.T) {
	k := newTestKey(t)
	pub, err := ParsePublicKey(FormatPublicKey(k.pub))
	if err != nil || !pub.Equal(k.pub) {
		t.Fatalf("public key round trip: %v", err)
	}
	priv, err := ParsePrivateKey(FormatPrivateKey(k.priv) + "\n")
	if err != nil || !priv.Equal(k.priv) {
		t.Fatalf("private key round trip: %v", err)
	}
	for _, s := range []string{"", "ed25519:", "ed25519:AAAA", base64.StdEncoding.EncodeToString(k.pub), "ed25519-seed:" + base64.StdEncoding.EncodeToString(k.pub)} {
		if _, err := ParsePublicKey(s); err == nil && !strings.HasPrefix(s, "ed25519-seed") {
			t.Errorf("ParsePublicKey(%q) succeeded", s)
		}
	}
	if _, err := ParsePrivateKey(FormatPublicKey(k.pub)); err == nil {
		t.Error("public key parsed as private key")
	}
}

func TestDetachedArtifactSignature(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	data := []byte("artifact bytes")
	sigs, err := SignArtifact(bytes.NewReader(data), k.priv)
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := VerifyArtifact(bytes.NewReader(data), sigs, k.trust(), testNow); err != nil || len(ids) != 1 {
		t.Fatalf("verify: %v %v", ids, err)
	}
	if _, err := VerifyArtifact(bytes.NewReader([]byte("artifact byteS")), sigs, k.trust(), testNow); !errors.Is(err, ErrUnsigned) {
		t.Errorf("tampered artifact: %v", err)
	}
	if _, err := VerifyArtifact(bytes.NewReader(data), sigs, other.trust(), testNow); !errors.Is(err, ErrUnsigned) {
		t.Errorf("untrusted key: %v", err)
	}
	// A manifest signature is not an artifact signature, and back.
	signed := mustSign(t, sampleManifest(), k)
	var env envelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArtifact(bytes.NewReader(env.Payload), env.Signatures, k.trust(), testNow); !errors.Is(err, ErrUnsigned) {
		t.Errorf("cross-context signature accepted: %v", err)
	}
}

func FuzzOpenManifest(f *testing.F) {
	k := newTestKey(f)
	f.Add(mustSign(f, sampleManifest(), k))
	f.Add([]byte(`{"payload":"e30=","signatures":[]}`))
	f.Add([]byte(`{}`))
	trust := k.trust()
	insecure := Trust{InsecureSkipSignature: true}
	f.Fuzz(func(t *testing.T, data []byte) {
		if o, err := OpenManifest(data, trust, testNow); err == nil && (o == nil || o.Manifest == nil || len(o.KeyIDs) == 0) {
			t.Fatal("accepted without a signer")
		}
		if o, err := OpenManifest(data, insecure, testNow); err == nil {
			if o == nil || o.Manifest == nil || o.Manifest.validate() != nil || !testNow.Before(o.Manifest.Expires) {
				t.Fatal("accepted an invalid manifest")
			}
		}
	})
}

func TestPayloadStrict(t *testing.T) {
	k := newTestKey(t)
	base, err := json.Marshal(sampleManifest())
	must(t, err)
	for name, payload := range map[string]string{
		"unknown field":    strings.Replace(string(base), `"product"`, `"extra":1,"product"`, 1),
		"duplicate key":    strings.Replace(string(base), `"product":"app"`, `"product":"app","product":"evil"`, 1),
		"case duplicate":   strings.Replace(string(base), `"product":"app"`, `"product":"app","Product":"evil"`, 1),
		"nested duplicate": strings.Replace(string(base), `"version":"1.2.0"`, `"version":"1.2.0","version":"9.0.0"`, 1),
		"trailing":         string(base) + "{}",
	} {
		sigs, err := sign(manifestContext, []byte(payload), []ed25519.PrivateKey{k.priv})
		must(t, err)
		data, err := json.Marshal(envelope{Payload: []byte(payload), Signatures: sigs})
		must(t, err)
		if _, err := OpenManifest(data, k.trust(), testNow); !errors.Is(err, ErrMalformedManifest) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestManifestValidation covers manifests that used to be accepted:
// closing brackets after the document (regression), no publication time,
// ambiguous artifacts and versions, and a threshold no keys can meet.
func TestManifestValidation(t *testing.T) {
	k := newTestKey(t)
	signed := mustSign(t, sampleManifest(), k)
	for _, tail := range []string{"}", "]", " } "} {
		if _, err := OpenManifest(append(bytes.Clone(signed), tail...), k.trust(), testNow); !errors.Is(err, ErrMalformedManifest) {
			t.Errorf("trailing %q: %v", tail, err)
		}
	}
	base, err := json.Marshal(sampleManifest())
	must(t, err)
	if _, err := DecodeManifest(append(base, ']')); !errors.Is(err, ErrMalformedManifest) {
		t.Errorf("payload trailing bracket: %v", err)
	}
	app := artifactFor("app", "a", FormatRaw, []byte("x"))
	linux := app
	linux.OS = "linux"
	for name, m := range map[string]*Manifest{
		"no published":       {Product: "p", Expires: testNow},
		"published late":     {Product: "p", Published: testNow, Expires: testNow},
		"duplicate version":  manifestOf("p", Release{Version: "1.0.0"}, Release{Version: "1.0.0+build"}),
		"duplicate artifact": manifestOf("p", Release{Version: "1.0.0", Artifacts: []Artifact{app, app}}),
		"overlap":            manifestOf("p", Release{Version: "1.0.0", Artifacts: []Artifact{app, linux}}),
	} {
		if _, err := SignManifest(m, k.priv); !errors.Is(err, ErrMalformedManifest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	windows := linux
	windows.OS = "windows"
	if _, err := SignManifest(manifestOf("p", Release{Version: "1.0.0", Artifacts: []Artifact{linux, windows}}), k.priv); err != nil {
		t.Errorf("distinct platforms: %v", err)
	}
	for name, trust := range map[string]Trust{
		"threshold": {Keys: []TrustedKey{{Public: k.pub}, {Public: k.pub}}, Threshold: 2},
		"bad key":   {Keys: []TrustedKey{{Public: k.pub[:5]}}},
	} {
		if _, err := OpenManifest(signed, trust, testNow); !errors.Is(err, ErrBadTrust) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
