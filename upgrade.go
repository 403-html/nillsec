package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// upgradeAPIURL is the GitHub Releases API endpoint; overridable in tests.
var upgradeAPIURL = "https://api.github.com/repos/403-html/nillsec/releases/latest"

// upgradeHTTPClient is used for all upgrade HTTP requests.
var upgradeHTTPClient = &http.Client{Timeout: 2 * time.Minute}

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
	parsed, err := parseSemanticVersion(v)
	if err != nil {
		return 0, err
	}
	return parsed.major, nil
}

type semanticVersion struct {
	major, minor, patch int
	prerelease          string
}

func parseSemanticVersion(input string) (semanticVersion, error) {
	original := input
	input = strings.TrimPrefix(input, "v")
	if plus := strings.IndexByte(input, '+'); plus >= 0 {
		input = input[:plus]
	}
	prerelease := ""
	if dash := strings.IndexByte(input, '-'); dash >= 0 {
		prerelease = input[dash+1:]
		input = input[:dash]
		if prerelease == "" {
			return semanticVersion{}, fmt.Errorf("invalid version %q", original)
		}
	}
	parts := strings.Split(input, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semanticVersion{}, fmt.Errorf("invalid version %q", original)
	}
	numbers := [3]int{}
	for i, part := range parts {
		if part == "" {
			return semanticVersion{}, fmt.Errorf("invalid version %q", original)
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return semanticVersion{}, fmt.Errorf("invalid version %q", original)
		}
		numbers[i] = n
	}
	return semanticVersion{major: numbers[0], minor: numbers[1], patch: numbers[2], prerelease: prerelease}, nil
}

// compareSemanticVersions returns -1, 0, or 1 when a is older than, equal to,
// or newer than b.
func compareSemanticVersions(a, b string) (int, error) {
	av, err := parseSemanticVersion(a)
	if err != nil {
		return 0, err
	}
	bv, err := parseSemanticVersion(b)
	if err != nil {
		return 0, err
	}
	for _, pair := range [][2]int{{av.major, bv.major}, {av.minor, bv.minor}, {av.patch, bv.patch}} {
		if pair[0] < pair[1] {
			return -1, nil
		}
		if pair[0] > pair[1] {
			return 1, nil
		}
	}
	return comparePrerelease(av.prerelease, bv.prerelease), nil
}

func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return 1
	}
	if b == "" {
		return -1
	}
	aParts, bParts := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		if aParts[i] == bParts[i] {
			continue
		}
		aNum, aErr := strconv.Atoi(aParts[i])
		bNum, bErr := strconv.Atoi(bParts[i])
		switch {
		case aErr == nil && bErr == nil:
			if aNum < bNum {
				return -1
			}
			return 1
		case aErr == nil:
			return -1
		case bErr == nil:
			return 1
		case aParts[i] < bParts[i]:
			return -1
		default:
			return 1
		}
	}
	if len(aParts) < len(bParts) {
		return -1
	}
	return 1
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
	comparison, err := compareSemanticVersions(version, latest)
	if err != nil {
		return fmt.Errorf("comparing current and latest versions: %w", err)
	}
	if comparison == 0 {
		fmt.Printf("nillsec is already up to date (%s).\n", version)
		return nil
	}
	if comparison > 0 {
		fmt.Printf("nillsec %s is newer than the latest published release (%s); no update performed.\n", version, latest)
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
	var downloadURL, checksumURL string
	for _, asset := range rel.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
		}
		if asset.Name == "checksums.txt" {
			checksumURL = asset.BrowserDownloadURL
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (expected %q)", runtime.GOOS, runtime.GOARCH, assetName)
	}
	if checksumURL == "" {
		return fmt.Errorf("release is missing checksums.txt; refusing an unverified update")
	}
	expectedChecksum, err := fetchExpectedChecksum(checksumURL, assetName)
	if err != nil {
		return fmt.Errorf("fetching release checksum: %w", err)
	}

	exePath, err := executableFn()
	if err != nil {
		return fmt.Errorf("finding executable path: %w", err)
	}

	fmt.Printf("Downloading %s...\n", assetName)
	if err := downloadAndInstall(downloadURL, assetName, exePath, expectedChecksum); err != nil {
		return fmt.Errorf("installing update: %w", err)
	}

	fmt.Printf("nillsec updated to %s.\n", latest)
	return nil
}

// fetchLatestRelease queries the GitHub Releases API for the latest release.
func fetchLatestRelease() (*githubRelease, error) {
	if err := validateUpgradeURL(upgradeAPIURL); err != nil {
		return nil, err
	}
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
	if err := validateUpgradeURL(resp.Request.URL.String()); err != nil {
		return nil, err
	}

	var rel githubRelease
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(data) > maxReleaseMetadataBytes {
		return nil, fmt.Errorf("GitHub API response is larger than %d bytes", maxReleaseMetadataBytes)
	}
	if err := json.Unmarshal(data, &rel); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &rel, nil
}

const (
	// maxDownloadBytes is the maximum release artifact or extracted binary size.
	maxDownloadBytes        = 50 << 20
	maxChecksumBytes        = 1 << 20
	maxReleaseMetadataBytes = 1 << 20
)

// validateUpgradeURL prevents transport downgrades. Loopback HTTP is accepted
// only to allow local integration tests without weakening real downloads.
func validateUpgradeURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid upgrade URL %q", rawURL)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && (strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing insecure upgrade URL %q", rawURL)
}

// fetchExpectedChecksum downloads checksums.txt and returns the selected
// artifact's validated SHA-256 digest.
func fetchExpectedChecksum(url, assetName string) ([]byte, error) {
	manifest, err := downloadBytes(url, maxChecksumBytes)
	if err != nil {
		return nil, err
	}

	var result []byte
	scanner := bufio.NewScanner(strings.NewReader(string(manifest)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != assetName {
			continue
		}
		if result != nil {
			return nil, fmt.Errorf("checksum file contains duplicate entries for %q", assetName)
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 checksum for %q", assetName)
		}
		result = digest
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading checksum file: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("checksum file has no entry for %q", assetName)
	}
	return result, nil
}

func downloadBytes(url string, limit int64) ([]byte, error) {
	if err := validateUpgradeURL(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nillsec/"+version)
	resp, err := upgradeHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: HTTP %s", resp.Status)
	}
	if err := validateUpgradeURL(resp.Request.URL.String()); err != nil {
		return nil, err
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("download is larger than %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("download is larger than %d bytes", limit)
	}
	return data, nil
}

// downloadAndInstall downloads the new binary from url, extracts it from a
// tar.gz archive if necessary, and atomically replaces the binary at exePath.
func downloadAndInstall(url, assetName, exePath string, expectedChecksum []byte) error {
	if len(expectedChecksum) != sha256.Size {
		return errors.New("missing or invalid expected SHA-256 checksum")
	}

	if err := validateUpgradeURL(url); err != nil {
		return err
	}
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
	if err := validateUpgradeURL(resp.Request.URL.String()); err != nil {
		return err
	}
	if resp.ContentLength > maxDownloadBytes {
		return fmt.Errorf("release artifact is larger than %d bytes", maxDownloadBytes)
	}

	// Download the complete release artifact first so the checksum covers the
	// archive itself, exactly as listed by checksums.txt.
	asset, err := os.CreateTemp("", ".nillsec-download-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	assetNameOnDisk := asset.Name()
	defer func() {
		_ = asset.Close()
		_ = os.Remove(assetNameOnDisk)
	}()

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(asset, hasher), io.LimitReader(resp.Body, maxDownloadBytes+1)) //nolint:gosec
	if err != nil {
		return fmt.Errorf("downloading release artifact: %w", err)
	}
	if written > maxDownloadBytes {
		return fmt.Errorf("release artifact is larger than %d bytes", maxDownloadBytes)
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expectedChecksum) != 1 {
		return errors.New("release artifact checksum mismatch; refusing update")
	}
	if err := asset.Sync(); err != nil {
		return fmt.Errorf("flushing downloaded artifact: %w", err)
	}
	if _, err := asset.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewinding downloaded artifact: %w", err)
	}

	// Extract or copy the verified executable into a separate private file.
	tmp, err := os.CreateTemp("", ".nillsec-upgrade-*")
	if err != nil {
		return fmt.Errorf("creating executable temp file: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()

	if strings.HasSuffix(assetName, ".tar.gz") {
		gz, err := gzip.NewReader(asset)
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
				if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
					return fmt.Errorf("binary %q is not a regular archive entry", binaryName)
				}
				if hdr.Size < 0 || hdr.Size > maxDownloadBytes {
					return fmt.Errorf("binary %q is larger than %d bytes", binaryName, maxDownloadBytes)
				}
				if _, err := io.CopyN(tmp, tr, hdr.Size); err != nil { //nolint:gosec
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
		if _, err := io.Copy(tmp, asset); err != nil { //nolint:gosec
			return fmt.Errorf("writing binary: %w", err)
		}
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("setting file permissions: %w", err)
	}

	// Attempt an atomic rename. This works when the temp directory and the
	// binary directory share the same filesystem.
	if err := os.Rename(tmpName, exePath); err != nil {
		// Rename may fail with a cross-device error when the system temp
		// directory and the binary directory are on different filesystems.
		// Fall back to copying the downloaded file into a temp file inside
		// the destination directory and renaming from there.
		//
		// For any other error (e.g. permission denied), the fallback will not
		// help either, so surface the error directly with a useful hint.
		var linkErr *os.LinkError
		if !errors.As(err, &linkErr) || !errors.Is(linkErr.Err, syscall.EXDEV) {
			if os.IsPermission(err) {
				return fmt.Errorf("replacing binary (try running with elevated privileges, e.g. sudo): %w", err)
			}
			return fmt.Errorf("replacing binary: %w", err)
		}
		if err2 := installViaDestDir(tmpName, exePath); err2 != nil {
			return err2
		}
		os.Remove(tmpName) //nolint:errcheck
	}

	ok = true
	return nil
}

// installViaDestDir copies the file at srcPath into a temp file in the same
// directory as dstPath, sets executable permissions, then renames it over
// dstPath. It is used as a fallback when a cross-filesystem rename is not
// possible.
func installViaDestDir(srcPath, dstPath string) error {
	dir := filepath.Dir(dstPath)
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

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("reopening downloaded file: %w", err)
	}
	defer src.Close()

	if _, err := io.Copy(tmp, src); err != nil {
		return fmt.Errorf("copying to binary directory: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("setting file permissions: %w", err)
	}

	if err := os.Rename(tmpName, dstPath); err != nil {
		return fmt.Errorf("replacing binary (try with elevated privileges): %w", err)
	}

	ok = true
	return nil
}
