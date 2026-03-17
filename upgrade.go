package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// upgradeAPIURL is the GitHub Releases API endpoint; overridable in tests.
var upgradeAPIURL = "https://api.github.com/repos/403-html/nillsec/releases/latest"

// upgradeHTTPClient is used for all upgrade HTTP requests.
var upgradeHTTPClient = &http.Client{Timeout: 30 * time.Second}

// executableFn returns the path to the running binary; overridable in tests.
var executableFn = os.Executable

// githubRelease holds the fields we need from the GitHub Releases API.
type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// parseMajorVersion returns the major version number from a semver string
// such as "v1.2.3" or "2.0.0".
func parseMajorVersion(v string) (int, error) {
	v = strings.TrimPrefix(v, "v")
	if dot := strings.IndexByte(v, '.'); dot >= 0 {
		v = v[:dot]
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid version %q: %w", v, err)
	}
	return n, nil
}

// upgradeAssetName returns the expected GitHub release asset filename for the
// current OS and CPU architecture.
func upgradeAssetName() string {
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv7"
	}
	name := fmt.Sprintf("nillsec-%s-%s", runtime.GOOS, arch)
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name + ".tar.gz"
}

// cmdUpgrade checks for a newer release on GitHub and, if found, downloads and
// replaces the running binary.
func cmdUpgrade() error {
	if version == "dev" {
		fmt.Fprintln(os.Stderr, "nillsec: upgrade is not available for development builds.")
		return nil
	}

	fmt.Println("Checking for updates...")

	rel, err := fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	latest := rel.TagName
	if latest == version {
		fmt.Printf("nillsec is already up to date (%s).\n", version)
		return nil
	}

	curMajor, err := parseMajorVersion(version)
	if err != nil {
		return fmt.Errorf("parsing current version %q: %w", version, err)
	}
	latestMajor, err := parseMajorVersion(latest)
	if err != nil {
		return fmt.Errorf("parsing latest version %q: %w", latest, err)
	}

	fmt.Printf("Update available: %s → %s\n", version, latest)

	if latestMajor > curMajor {
		fmt.Fprintf(os.Stderr, "Warning: this is a major version update (v%d → v%d) and may introduce breaking changes.\n", curMajor, latestMajor)
		fmt.Fprint(os.Stderr, "Are you sure you want to continue? [y/N] ")
		line, err := stdinReader.ReadString('\n')
		if err != nil && line == "" {
			// Unreadable stdin: default to "no" for safety.
			fmt.Fprintln(os.Stderr)
			fmt.Println("Upgrade cancelled.")
			return nil
		}
		answer := strings.TrimRight(line, "\r\n")
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			fmt.Println("Upgrade cancelled.")
			return nil
		}
	}

	assetName := upgradeAssetName()
	var downloadURL string
	for _, asset := range rel.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (expected %q)", runtime.GOOS, runtime.GOARCH, assetName)
	}

	exePath, err := executableFn()
	if err != nil {
		return fmt.Errorf("finding executable path: %w", err)
	}

	fmt.Printf("Downloading %s...\n", assetName)
	if err := downloadAndInstall(downloadURL, assetName, exePath); err != nil {
		return fmt.Errorf("installing update: %w", err)
	}

	fmt.Printf("nillsec updated to %s.\n", latest)
	return nil
}

// fetchLatestRelease queries the GitHub Releases API for the latest release.
func fetchLatestRelease() (*githubRelease, error) {
	req, err := http.NewRequest(http.MethodGet, upgradeAPIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "nillsec/"+version)

	resp, err := upgradeHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &rel, nil
}

// maxDownloadBytes is the maximum binary size we'll accept (50 MiB).
const maxDownloadBytes = 50 << 20

// downloadAndInstall downloads the new binary from url, extracts it from a
// tar.gz archive if necessary, and atomically replaces the binary at exePath.
func downloadAndInstall(url, assetName, exePath string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "nillsec/"+version)

	resp, err := upgradeHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %s", resp.Status)
	}

	// Write to a temp file in the same directory as the binary to ensure
	// os.Rename works (requires the same filesystem).
	dir := filepath.Dir(exePath)
	tmp, err := os.CreateTemp(dir, ".nillsec-upgrade-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %s (check write permissions): %w", dir, err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(tmpName) //nolint:errcheck
		}
	}()

	body := io.LimitReader(resp.Body, maxDownloadBytes)
	if strings.HasSuffix(assetName, ".tar.gz") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return fmt.Errorf("reading gzip: %w", err)
		}
		defer gz.Close()

		binaryName := strings.TrimSuffix(assetName, ".tar.gz")
		tr := tar.NewReader(gz)
		found := false
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("reading tar: %w", err)
			}
			if hdr.Name == binaryName {
				if _, err := io.Copy(tmp, io.LimitReader(tr, maxDownloadBytes)); err != nil { //nolint:gosec
					return fmt.Errorf("writing binary: %w", err)
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("binary %q not found in archive", binaryName)
		}
	} else {
		if _, err := io.Copy(tmp, body); err != nil { //nolint:gosec
			return fmt.Errorf("writing binary: %w", err)
		}
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("setting file permissions: %w", err)
	}

	if err := os.Rename(tmpName, exePath); err != nil {
		return fmt.Errorf("replacing binary (try with elevated privileges): %w", err)
	}

	ok = true
	return nil
}
