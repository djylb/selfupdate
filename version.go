package selfupdate

import (
	"cmp"
	"errors"
	"strconv"
	"strings"
)

// ErrInvalidVersion reports a version string that is not a semantic version.
var ErrInvalidVersion = errors.New("selfupdate: invalid semantic version")

// Version is a parsed semantic version (https://semver.org, 2.0.0).
// The zero value is 0.0.0.
type Version struct {
	// Pre holds the dot-separated pre-release identifiers, if any.
	Pre []string
	// Build holds the build metadata after "+", which never affects ordering.
	Build string
	// Major, Minor and Patch are the numeric release components.
	Major, Minor, Patch uint64
}

// ParseVersion parses s as a semantic version. A leading "v" is accepted,
// as are omitted minor and patch components ("1" and "1.2" mean 1.0.0 and
// 1.2.0); everything else follows the specification strictly.
func ParseVersion(s string) (Version, error) {
	var v Version
	s = strings.TrimPrefix(s, "v")
	s, build, hasBuild := strings.Cut(s, "+")
	if hasBuild {
		if !validIdents(build, false) {
			return Version{}, ErrInvalidVersion
		}
		v.Build = build
	}
	core, pre, hasPre := strings.Cut(s, "-")
	if hasPre {
		if !validIdents(pre, true) {
			return Version{}, ErrInvalidVersion
		}
		v.Pre = strings.Split(pre, ".")
	}
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return Version{}, ErrInvalidVersion
	}
	nums := [3]*uint64{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		n, ok := parseNumeric(p)
		if !ok {
			return Version{}, ErrInvalidVersion
		}
		*nums[i] = n
	}
	return v, nil
}

func parseNumeric(p string) (uint64, bool) {
	if p == "" || (len(p) > 1 && p[0] == '0') {
		return 0, false
	}
	for i := range len(p) {
		if p[i] < '0' || p[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(p, 10, 64)
	return n, err == nil
}

// validIdents reports whether s is a non-empty list of dot-separated
// identifiers; pre-release numeric identifiers must not have leading zeros.
func validIdents(s string, pre bool) bool {
	if s == "" {
		return false
	}
	for id := range strings.SplitSeq(s, ".") {
		if id == "" {
			return false
		}
		numeric := true
		for i := range len(id) {
			c := id[i]
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				numeric = false
			default:
				return false
			}
		}
		if pre && numeric && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// String formats v in canonical form without a "v" prefix.
func (v Version) String() string {
	var b strings.Builder
	b.WriteString(strconv.FormatUint(v.Major, 10))
	b.WriteByte('.')
	b.WriteString(strconv.FormatUint(v.Minor, 10))
	b.WriteByte('.')
	b.WriteString(strconv.FormatUint(v.Patch, 10))
	if len(v.Pre) > 0 {
		b.WriteByte('-')
		b.WriteString(strings.Join(v.Pre, "."))
	}
	if v.Build != "" {
		b.WriteByte('+')
		b.WriteString(v.Build)
	}
	return b.String()
}

// IsPrerelease reports whether v carries pre-release identifiers.
func (v Version) IsPrerelease() bool { return len(v.Pre) > 0 }

// Compare returns -1, 0 or +1 as v orders before, equal to or after w
// under semantic version precedence. Build metadata is ignored.
func (v Version) Compare(w Version) int {
	if c := cmp.Compare(v.Major, w.Major); c != 0 {
		return c
	}
	if c := cmp.Compare(v.Minor, w.Minor); c != 0 {
		return c
	}
	if c := cmp.Compare(v.Patch, w.Patch); c != 0 {
		return c
	}
	switch {
	case len(v.Pre) == 0 && len(w.Pre) == 0:
		return 0
	case len(v.Pre) == 0:
		return 1
	case len(w.Pre) == 0:
		return -1
	}
	for i := range min(len(v.Pre), len(w.Pre)) {
		if c := compareIdent(v.Pre[i], w.Pre[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(v.Pre), len(w.Pre))
}

// compareIdent orders pre-release identifiers: numeric ones numerically
// (of any length; they have no leading zeros), before alphanumeric ones,
// which compare in ASCII order.
func compareIdent(a, b string) int {
	an, bn := isDigits(a), isDigits(b)
	switch {
	case an && bn:
		if c := cmp.Compare(len(a), len(b)); c != 0 {
			return c
		}
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

func isDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// CompareVersions parses a and b and compares them like [Version.Compare].
func CompareVersions(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}
