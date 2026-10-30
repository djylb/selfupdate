package selfupdate

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestPackageDependencies checks what the README promises: every package,
// tests included, depends on the standard library alone.
func TestPackageDependencies(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("cannot run the go command")
	}
	goCmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	if gomod, err := exec.Command(goCmd, "env", "GOMOD").Output(); err != nil || !strings.HasSuffix(strings.TrimSpace(string(gomod)), "go.mod") {
		t.Skip("not run from the module source")
	}
	const module = "github.com/djylb/selfupdate"
	allowed := map[string][]string{
		module:                     nil,
		module + "/cmd/selfupdate": {module},
	}
	listed, err := exec.Command(goCmd, "list", module+"/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for line := range strings.Lines(string(listed)) {
		if _, ok := allowed[strings.TrimSpace(line)]; !ok {
			t.Errorf("package %s has no dependency rule", strings.TrimSpace(line))
		}
	}
	for pkg, internal := range allowed {
		out, err := exec.Command(goCmd, "list", "-deps", "-test", "-f", "{{.ImportPath}} {{.Standard}}", pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for line := range strings.Lines(string(out)) {
			path, std, _ := strings.Cut(strings.TrimSpace(line), " ")
			path, _, _ = strings.Cut(path, " ")
			switch {
			case path == pkg || path == pkg+".test" || strings.HasPrefix(path, pkg+"_test"):
			case strings.HasPrefix(path, module):
				ok := false
				for _, p := range internal {
					ok = ok || p == path
				}
				if !ok {
					t.Errorf("%s depends on %s", pkg, path)
				}
			case std != "true":
				t.Errorf("%s depends on %s outside the standard library", pkg, path)
			}
		}
	}
}
