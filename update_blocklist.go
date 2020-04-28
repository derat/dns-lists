package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// URL of file listing regular expressions matching always-permitted zones.
	allowPatternsURL = "https://raw.githubusercontent.com/derat/dns-lists/master/allow-patterns"
	// Path where the Unbound config file will be written.
	configPath = "/etc/unbound/unbound.conf.d/blocklist.conf"
)

// URLs of hosts files listing zones to deny.
// Entries should be mapped to "0.0.0.0".
var denyHostsURLs = []string{
	"https://raw.githubusercontent.com/derat/dns-lists/master/deny-hosts",
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
}

// Matches valid zone names.
var zoneRegexp = regexp.MustCompile("^[-_.a-zA-Z0-9]+$")

func main() {
	var dryRun = flag.String("dry-run", "", "Write to the supplied path and don't restart Unbound")
	flag.Parse()

	allowPats, err := fetchRegexpFile(allowPatternsURL)
	if err != nil {
		log.Fatalf("Failed to read patterns from %v: %v", allowPatternsURL, err)
	}

	destPath := configPath
	if len(*dryRun) > 0 {
		destPath = *dryRun
	}
	fw, err := newFileWriter(destPath)
	if err != nil {
		log.Fatal("Failed to create temp file: ", err)
	}
	defer fw.close()

	// Use log.Panic/Panicf from here on to run deferred functions.
	fmt.Fprintf(fw, "# Written on %s\n", time.Now().Format(time.RFC1123))
	for _, url := range denyHostsURLs {
		fmt.Fprintf(fw, "\n# %s\n", url)
		if err := writeZones(fw, url, allowPats); err != nil {
			log.Panicf("Failed to write zones from %v: %v", url, err)
		}
	}
	if err := fw.finish(); err != nil {
		log.Panic("Failed to finish file: ", err)
	}

	if len(*dryRun) == 0 {
		if err := runCmd("unbound-checkconf", destPath); err != nil {
			log.Panic("Failed to check config: ", err)
		}
		if err := runCmd("service", "unbound", "restart"); err != nil {
			log.Panic("Failed to restart unbound service: ", err)
		}
	}
}

// fetchRegexpFile fetches the file at the supplied URL and compiles each line
// into a regular expression. Leading and trailing whitespace is trimmed and
// lines starting with a '#' are skipped.
func fetchRegexpFile(url string) ([]*regexp.Regexp, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var pats []*regexp.Regexp
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}
		re, err := regexp.Compile(ln)
		if err != nil {
			return nil, fmt.Errorf("failed to compile %q: %v", ln, err)
		}
		pats = append(pats, re)
	}
	return pats, nil
}

// writeZones fetches the file at the supplied URL and writes Unbound local-zone
// "refuse" entries to w. Zones matched by patterns in allowPats are skipped.
func writeZones(w io.Writer, url string, allowPats []*regexp.Regexp) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
loop:
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}
		fields := strings.Fields(ln)
		if len(fields) < 2 || fields[0] != "0.0.0.0" || fields[1] == "0.0.0.0" {
			continue
		}
		zone := fields[1]
		if !zoneRegexp.MatchString(zone) {
			log.Printf("Skipping bad zone %q in %v", zone, url)
			continue
		}
		for _, p := range allowPats {
			if p.MatchString(zone) {
				continue loop
			}
		}
		if _, err := fmt.Fprintf(w, "local-zone: \"%s\" refuse\n", zone); err != nil {
			return err
		}
	}
	return nil
}

// runCmd synchronously runs the supplied command and returns an error
// containing stdout and stderr on failure.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v %v: %v", name, strings.Join(args, " "), string(out))
	}
	return nil
}

// fileWriter writes to a temp file and then renames it on completion.
type fileWriter struct {
	p       string   // dest path
	f       *os.File // temp file
	err     error    // first error returned by a Write call
	closed  bool     // f.Close() has been called
	renamed bool     // f has been renamed to p
}

// newFileWriter returns a new fileWriter that will write to a temp file that
// will eventually replace p.
func newFileWriter(p string) (*fileWriter, error) {
	// Use a '.tmp' extension since Unbound reads *.conf by default.
	f, err := ioutil.TempFile(filepath.Dir(p), "."+filepath.Base(p)+".*.tmp")
	if err != nil {
		return nil, err
	}
	return &fileWriter{p: p, f: f}, nil
}

// close cleans up resources if an error occurred earlier.
// It always returns nil.
func (fw *fileWriter) close() error {
	if !fw.closed {
		fw.f.Close()
	}
	if !fw.renamed {
		os.Remove(fw.f.Name())
	}
	return nil
}

// Write implements os.Writer. Errors are deferred.
func (fw *fileWriter) Write(p []byte) (n int, err error) {
	if fw.err == nil {
		_, fw.err = fw.f.Write(p)
	}
	return len(p), nil // swallow errors
}

// finish closes the temp file and renames it to the original path.
func (fw *fileWriter) finish() error {
	// Report earlier write error.
	if fw.err != nil {
		return fw.err
	}

	if err := fw.f.Close(); err != nil {
		return err
	}
	fw.closed = true

	if err := os.Rename(fw.f.Name(), fw.p); err != nil {
		return err
	}
	fw.renamed = true

	return nil
}
