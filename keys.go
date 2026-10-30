package selfupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// Domain separation prefixes: a signature over a manifest can never be
// presented as a signature over an artifact digest, or the other way round.
const (
	manifestContext = "selfupdate manifest v1\n"
	artifactContext = "selfupdate artifact v1\n"
)

// Errors returned by signature verification.
var (
	ErrNoTrustedKeys = errors.New("selfupdate: no trusted keys configured")
	ErrUnsigned      = errors.New("selfupdate: not signed by enough trusted keys")
	ErrInvalidKey    = errors.New("selfupdate: invalid key")
)

// Signature is one Ed25519 signature together with the ID of the key that
// made it.
type Signature struct {
	// KeyID is [KeyID] of the signing public key.
	KeyID string `json:"key_id"`
	// Sig is the raw 64-byte Ed25519 signature.
	Sig []byte `json:"sig"`
}

// TrustedKey is a public key the caller accepts signatures from.
type TrustedKey struct {
	// NotAfter, when set, ends the key's validity: signatures by the key
	// are rejected once the current time passes it. Use it to retire a key
	// during rotation after its successor has been deployed.
	NotAfter time.Time
	// Public is the Ed25519 public key.
	Public ed25519.PublicKey
}

// Trust is a signature policy.
//
// The zero value trusts nobody and rejects everything. To rotate keys,
// ship a release that trusts both the old and the new key, sign with both
// for a while, then drop the old key (or let its NotAfter pass).
type Trust struct {
	// Keys lists the trusted public keys.
	Keys []TrustedKey
	// Threshold is the number of distinct trusted keys that must have
	// signed. Zero means one.
	Threshold int
	// InsecureSkipSignature turns signature checks off. Content is then
	// only as trustworthy as the channel it was fetched over; digests are
	// still checked. Never set it for updates fetched over a network you
	// do not control.
	InsecureSkipSignature bool
}

// KeyID returns the identifier of pub: the hex encoding of the first eight
// bytes of its SHA-256 digest.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// GenerateKey returns a new Ed25519 key pair drawn from crypto/rand.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// FormatPublicKey encodes pub as "ed25519:" followed by standard base64,
// the form [ParsePublicKey] reads.
func FormatPublicKey(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey decodes a key written by [FormatPublicKey].
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := decodeKey(s, "ed25519:", ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

// FormatPrivateKey encodes the seed of priv as "ed25519-seed:" followed by
// standard base64, the form [ParsePrivateKey] reads.
func FormatPrivateKey(priv ed25519.PrivateKey) string {
	return "ed25519-seed:" + base64.StdEncoding.EncodeToString(priv.Seed())
}

// ParsePrivateKey decodes a key written by [FormatPrivateKey].
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := decodeKey(s, "ed25519-seed:", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(b), nil
}

func decodeKey(s, prefix string, size int) ([]byte, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), prefix)
	if !ok {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrInvalidKey, prefix)
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(b) != size {
		return nil, ErrInvalidKey
	}
	return b, nil
}

// sign signs context+msg with every key.
func sign(context string, msg []byte, keys []ed25519.PrivateKey) ([]Signature, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidKey
	}
	data := append([]byte(context), msg...)
	sigs := make([]Signature, 0, len(keys))
	for _, k := range keys {
		if len(k) != ed25519.PrivateKeySize {
			return nil, ErrInvalidKey
		}
		pub, _ := k.Public().(ed25519.PublicKey)
		sigs = append(sigs, Signature{KeyID: KeyID(pub), Sig: ed25519.Sign(k, data)})
	}
	return sigs, nil
}

// verify returns the IDs of the trusted keys with a valid signature over
// context+msg, or an error unless they reach the threshold.
func (t Trust) verify(context string, msg []byte, sigs []Signature, now time.Time) ([]string, error) {
	if t.InsecureSkipSignature {
		return nil, nil
	}
	if len(t.Keys) == 0 {
		return nil, ErrNoTrustedKeys
	}
	need := max(t.Threshold, 1)
	data := append([]byte(context), msg...)
	var ok []string
	for _, s := range sigs {
		if len(s.Sig) != ed25519.SignatureSize {
			continue
		}
		for _, k := range t.Keys {
			if len(k.Public) != ed25519.PublicKeySize || KeyID(k.Public) != s.KeyID {
				continue
			}
			if !k.NotAfter.IsZero() && now.After(k.NotAfter) {
				continue
			}
			if !slices.Contains(ok, s.KeyID) && ed25519.Verify(k.Public, data, s.Sig) {
				ok = append(ok, s.KeyID)
			}
		}
	}
	if len(ok) < need {
		return nil, ErrUnsigned
	}
	return ok, nil
}

// SignArtifact reads r to the end and returns detached signatures over its
// SHA-512 digest, one per key. Use it to sign files distributed without a
// manifest; [VerifyArtifact] checks them.
func SignArtifact(r io.Reader, keys ...ed25519.PrivateKey) ([]Signature, error) {
	h := sha512.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return sign(artifactContext, h.Sum(nil), keys)
}

// VerifyArtifact reads r to the end and checks the detached signatures made
// by [SignArtifact] against t at time now. It returns the IDs of the keys
// whose signatures were valid.
func VerifyArtifact(r io.Reader, sigs []Signature, t Trust, now time.Time) ([]string, error) {
	h := sha512.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return t.verify(artifactContext, h.Sum(nil), sigs, now)
}
