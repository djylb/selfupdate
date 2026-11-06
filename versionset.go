package selfupdate

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUpgradeFromRejected reports that a new version refuses to take over from
// the running one. The refusal is final for that artifact and source version,
// so an [Updater] remembers it and routes around it; see [CheckUpgradeFrom].
var ErrUpgradeFromRejected = errors.New("selfupdate: new version does not accept this source version")

type setOp int

const (
	opEq setOp = iota
	opGt
	opGe
	opLt
	opLe
)

type setClause struct {
	v  Version
	op setOp
}

func (c setClause) matches(v Version) bool {
	o := v.Compare(c.v)
	switch c.op {
	case opEq:
		return o == 0
	case opGt:
		return o > 0
	case opGe:
		return o >= 0
	case opLt:
		return o < 0
	default:
		return o <= 0
	}
}

// VersionSet is a set of versions in full semantic version order, parsed
// by [ParseVersionSet]. The zero value contains nothing.
type VersionSet struct {
	text   string
	groups [][]setClause
}

// ParseVersionSet parses "*", or groups separated by "||" of space-separated
// comparisons (=, >, >=, <, <=) that must all hold. Pre-releases order below
// their release, so a boundary that also covers the pre-releases of 2.0.0 is
// written ">=2.0.0-0" and "<2.0.0-0".
func ParseVersionSet(s string) (VersionSet, error) {
	set := VersionSet{text: strings.TrimSpace(s)}
	if set.text == "*" {
		set.groups = [][]setClause{nil}
		return set, nil
	}
	for group := range strings.SplitSeq(s, "||") {
		fields := strings.Fields(group)
		if len(fields) == 0 {
			return VersionSet{}, fmt.Errorf("selfupdate: version set %q: empty group", s)
		}
		clauses := make([]setClause, 0, len(fields))
		for _, f := range fields {
			var c setClause
			switch {
			case strings.HasPrefix(f, ">="):
				c.op, f = opGe, f[2:]
			case strings.HasPrefix(f, "<="):
				c.op, f = opLe, f[2:]
			case strings.HasPrefix(f, ">"):
				c.op, f = opGt, f[1:]
			case strings.HasPrefix(f, "<"):
				c.op, f = opLt, f[1:]
			case strings.HasPrefix(f, "="):
				c.op, f = opEq, f[1:]
			default:
				return VersionSet{}, fmt.Errorf("selfupdate: version set %q: %q has no comparison", s, f)
			}
			v, err := ParseVersion(f)
			if err != nil {
				return VersionSet{}, fmt.Errorf("selfupdate: version set %q: %w", s, err)
			}
			c.v = v
			clauses = append(clauses, c)
		}
		set.groups = append(set.groups, clauses)
	}
	return set, nil
}

// MustVersionSet is [ParseVersionSet] for constants; it panics on an error.
func MustVersionSet(s string) VersionSet {
	set, err := ParseVersionSet(s)
	if err != nil {
		panic(err)
	}
	return set
}

// Contains reports whether v is in the set.
func (s VersionSet) Contains(v Version) bool {
	for _, g := range s.groups {
		ok := true
		for _, c := range g {
			ok = ok && c.matches(v)
		}
		if ok {
			return true
		}
	}
	return false
}

// String returns the set as it was written.
func (s VersionSet) String() string { return s.text }

// CheckUpgradeFrom reports whether a version may take over from the version
// from. A new version compiles in the set it accepts, next to its migration
// code, and calls this before replacing the old one (from [Updater].Verify,
// running the staged program) and on its first start. The error wraps
// [ErrUpgradeFromRejected].
func CheckUpgradeFrom(from string, allowed VersionSet) error {
	v, err := ParseVersion(from)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrUpgradeFromRejected, from, err)
	}
	if !allowed.Contains(v) {
		return fmt.Errorf("%w: %s is not in %s", ErrUpgradeFromRejected, from, allowed)
	}
	return nil
}
