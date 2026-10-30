package selfupdate

import "testing"

func TestVersionOrder(t *testing.T) {
	// Ascending, from the semantic versioning specification and more.
	order := []string{
		"0.9.9", "1.0.0-0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
		"1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
		"1.0.1", "1.2.0", "1.10.0", "2.0.0", "v18446744073709551615.0.0",
	}
	for i := range order {
		for j := range order {
			c, err := CompareVersions(order[i], order[j])
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if c != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", order[i], order[j], c, want)
			}
		}
	}
}

func TestParseVersion(t *testing.T) {
	good := map[string]string{
		"1":                     "1.0.0",
		"v1.2":                  "1.2.0",
		"1.2.3-rc.1+build.5":    "1.2.3-rc.1+build.5",
		"1.2.3+0001":            "1.2.3+0001",
		"1.0.0-x-y.0":           "1.0.0-x-y.0",
		"10.20.30-alpha-1.beta": "10.20.30-alpha-1.beta",
	}
	for in, want := range good {
		v, err := ParseVersion(in)
		if err != nil || v.String() != want {
			t.Errorf("ParseVersion(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
	bad := []string{"", "v", "1.2.3.4", "01.2.3", "1.02.3", "1.2.3-", "1.2.3+", "1.2.3-01", "1.2.3-a..b",
		"1.2.3-é", "-1.2.3", "1.2.x", "18446744073709551616.0.0", " 1.2.3", "1..2"}
	for _, in := range bad {
		if v, err := ParseVersion(in); err == nil {
			t.Errorf("ParseVersion(%q) = %v, want error", in, v)
		}
	}
	if c, _ := CompareVersions("1.0.0+a", "1.0.0+b"); c != 0 {
		t.Error("build metadata affects ordering")
	}
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"1.2.3", "v1.0.0-rc.1+x", "1.0.0-0.a", "0"} {
		f.Add(s, "1.0.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		va, err := ParseVersion(a)
		if err != nil {
			return
		}
		again, err := ParseVersion(va.String())
		if err != nil || again.Compare(va) != 0 || again.String() != va.String() {
			t.Fatalf("round trip of %q: %v %v", a, again, err)
		}
		vb, err := ParseVersion(b)
		if err != nil {
			return
		}
		if va.Compare(vb) != -vb.Compare(va) {
			t.Fatalf("asymmetric compare %q %q", a, b)
		}
	})
}

func TestHugeNumericPrerelease(t *testing.T) {
	c, err := CompareVersions("1.0.0-99999999999999999999", "1.0.0-100000000000000000000")
	if err != nil || c != -1 {
		t.Fatalf("got %d, %v", c, err)
	}
	if c, _ := CompareVersions("1.0.0-99999999999999999999", "1.0.0-a"); c != -1 {
		t.Fatal("numeric must sort before alphanumeric")
	}
}
