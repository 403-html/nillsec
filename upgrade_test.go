package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestParseMajorVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"v1.2.3", 1, false},
		{"v2.0.0", 2, false},
		{"v10.1.0", 10, false},
		{"1.0.0", 1, false}, // without 'v' prefix
		{"v0.1.0", 0, false},
		{"invalid", 0, true},
		{"v.1.0", 0, true},
	}
	for _, tt := range tests {
		got, err := parseMajorVersion(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseMajorVersion(%q) = %d, nil; want error", tt.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMajorVersion(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseMajorVersion(%q) = %d; want %d", tt.input, got, tt.want)
		}
	}
}

func TestCompareSemanticVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.4", -1},
		{"v1.10.0", "v1.9.9", 1},
		{"v2.0.0", "v2.0.0", 0},
		{"v2.0.0-rc.2", "v2.0.0-rc.10", -1},
		{"v2.0.0-rc.1", "v2.0.0", -1},
		{"1.2", "v1.2.0", 0},
	}
	for _, tt := range tests {
		got, err := compareSemanticVersions(tt.a, tt.b)
		if err != nil {
			t.Fatalf("compareSemanticVersions(%q, %q): %v", tt.a, tt.b, err)
		}
		if got != tt.want {
			t.Errorf("compareSemanticVersions(%q, %q) = %d; want %d", tt.a, tt.b, got, tt.want)
		}
	}
	if _, err := compareSemanticVersions("v1.2.3", "not-a-version"); err == nil {
		t.Fatal("compareSemanticVersions accepted malformed version")
	}
}

func TestValidateUpgradeURL(t *testing.T) {
	for _, accepted := range []string{"https://github.com/example", "http://127.0.0.1:8080/test", "http://localhost/test"} {
		if err := validateUpgradeURL(accepted); err != nil {
			t.Errorf("validateUpgradeURL(%q): %v", accepted, err)
		}
	}
	for _, rejected := range []string{"http://example.com/release", "file:///tmp/release", "://bad"} {
		if err := validateUpgradeURL(rejected); err == nil {
			t.Errorf("validateUpgradeURL(%q) unexpectedly succeeded", rejected)
		}
	}
}

func TestUpgradeAssetName(t *testing.T) {
	name := upgradeAssetName()

	if !strings.Contains(name, runtime.GOOS) {
		t.Errorf("asset name %q does not contain GOOS %q", name, runtime.GOOS)
	}

	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(name, ".exe") {
			t.Errorf("Windows asset name %q should end in .exe", name)
		}
	} else {
		if !strings.HasSuffix(name, ".tar.gz") {
			t.Errorf("non-Windows asset name %q should end in .tar.gz", name)
		}
	}

	if runtime.GOARCH == "arm" && !strings.Contains(name, "armv7") {
		t.Errorf("arm asset name %q should contain armv7", name)
	}
}

func TestCmdUpgradeDevVersion(t *testing.T) {
	origVersion := version
	t.Cleanup(func() { version = origVersion })
	version = "dev"

	if err := cmdUpgrade(); err != nil {
		t.Errorf("cmdUpgrade with dev version: unexpected error: %v", err)
	}
}

func TestCmdUpgradeAlreadyUpToDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := githubRelease{TagName: "v1.2.3"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rel); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	origVersion := version
	origAPIURL := upgradeAPIURL
	origClient := upgradeHTTPClient
	t.Cleanup(func() {
		version = origVersion
		upgradeAPIURL = origAPIURL
		upgradeHTTPClient = origClient
	})

	version = "v1.2.3"
	upgradeAPIURL = srv.URL
	upgradeHTTPClient = srv.Client()

	if err := cmdUpgrade(); err != nil {
		t.Errorf("cmdUpgrade (already up to date): unexpected error: %v", err)
	}
}

func TestCmdUpgradeRefusesOlderRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(githubRelease{TagName: "v1.9.9"})
	}))
	t.Cleanup(srv.Close)

	origVersion, origURL, origClient := version, upgradeAPIURL, upgradeHTTPClient
	t.Cleanup(func() {
		version, upgradeAPIURL, upgradeHTTPClient = origVersion, origURL, origClient
	})
	version = "v1.10.0"
	upgradeAPIURL = srv.URL
	upgradeHTTPClient = srv.Client()

	if err := cmdUpgrade(); err != nil {
		t.Fatalf("cmdUpgrade refused older release with error: %v", err)
	}
}

func TestCmdUpgradeRequiresChecksumsAsset(t *testing.T) {
	assetName := upgradeAssetName()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := githubRelease{TagName: "v1.3.0"}
		rel.Assets = append(rel.Assets, struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		}{Name: assetName, BrowserDownloadURL: srv.URL + "/asset"})
		_ = json.NewEncoder(w).Encode(rel)
	}))
	t.Cleanup(srv.Close)

	origVersion, origURL, origClient := version, upgradeAPIURL, upgradeHTTPClient
	t.Cleanup(func() {
		version, upgradeAPIURL, upgradeHTTPClient = origVersion, origURL, origClient
	})
	version = "v1.2.0"
	upgradeAPIURL = srv.URL
	upgradeHTTPClient = srv.Client()

	err := cmdUpgrade()
	if err == nil || !strings.Contains(err.Error(), "missing checksums.txt") {
		t.Fatalf("cmdUpgrade error = %v; want missing checksum refusal", err)
	}
}

func TestCmdUpgradeMajorVersionCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := githubRelease{TagName: "v2.0.0"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rel); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	origVersion := version
	origAPIURL := upgradeAPIURL
	origClient := upgradeHTTPClient
	origStdin := stdinReader
	t.Cleanup(func() {
		version = origVersion
		upgradeAPIURL = origAPIURL
		upgradeHTTPClient = origClient
		stdinReader = origStdin
	})

	version = "v1.0.0"
	upgradeAPIURL = srv.URL
	upgradeHTTPClient = srv.Client()
	stdinReader = bufio.NewReader(strings.NewReader("n\n"))

	if err := cmdUpgrade(); err != nil {
		t.Errorf("cmdUpgrade (major, cancelled): unexpected error: %v", err)
	}
}

// makeFakeTarGz creates a tar.gz archive in memory containing a single file
// with the given name and content.
func makeFakeTarGz(t *testing.T, binaryName, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	data := []byte(content)
	hdr := &tar.Header{
		Name: binaryName,
		Mode: 0o755,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("tar Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func TestFetchExpectedChecksum(t *testing.T) {
	want := sha256.Sum256([]byte("artifact"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%064x  other-file\n%x  nillsec-test.exe\n", 0, want)
	}))
	t.Cleanup(srv.Close)

	originalClient := upgradeHTTPClient
	t.Cleanup(func() { upgradeHTTPClient = originalClient })
	upgradeHTTPClient = srv.Client()
	got, err := fetchExpectedChecksum(srv.URL, "nillsec-test.exe")
	if err != nil {
		t.Fatalf("fetchExpectedChecksum: %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("checksum = %x; want %x", got, want)
	}
}

func TestFetchExpectedChecksumRejectsMalformedOrDuplicateEntry(t *testing.T) {
	for _, body := range []string{
		"not-a-digest  nillsec-test.exe\n",
		fmt.Sprintf("%064x  nillsec-test.exe\n%064x  nillsec-test.exe\n", 1, 2),
		fmt.Sprintf("%064x  another-file\n", 1),
	} {
		t.Run(strings.Split(body, "\n")[0], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			originalClient := upgradeHTTPClient
			defer func() { upgradeHTTPClient = originalClient }()
			upgradeHTTPClient = srv.Client()
			if _, err := fetchExpectedChecksum(srv.URL, "nillsec-test.exe"); err == nil {
				t.Fatal("fetchExpectedChecksum accepted invalid manifest")
			}
		})
	}
}

func TestDownloadAndInstallRejectsChecksumMismatch(t *testing.T) {
	data := []byte("new executable")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	originalClient := upgradeHTTPClient
	t.Cleanup(func() { upgradeHTTPClient = originalClient })
	upgradeHTTPClient = srv.Client()

	path := filepath.Join(t.TempDir(), "nillsec-test.exe")
	if err := os.WriteFile(path, []byte("old executable"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wrong := sha256.Sum256([]byte("different data"))
	err := downloadAndInstall(srv.URL, "nillsec-test.exe", path, wrong[:])
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("downloadAndInstall error = %v; want checksum mismatch", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "old executable" {
		t.Fatalf("executable changed after checksum failure: %q", got)
	}
}

func TestDownloadAndInstallRejectsOversizedArtifact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(maxDownloadBytes+1, 10))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	originalClient := upgradeHTTPClient
	t.Cleanup(func() { upgradeHTTPClient = originalClient })
	upgradeHTTPClient = srv.Client()
	digest := sha256.Sum256(nil)
	err := downloadAndInstall(srv.URL, "nillsec-test.exe", filepath.Join(t.TempDir(), "nillsec-test.exe"), digest[:])
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("downloadAndInstall error = %v; want size-limit error", err)
	}
}

func TestDownloadAndInstallRejectsNonRegularArchiveEntry(t *testing.T) {
	assetName := "nillsec-test.tar.gz"
	binaryName := strings.TrimSuffix(assetName, ".tar.gz")
	var archive bytes.Buffer
	gw := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: binaryName, Typeflag: tar.TypeSymlink, Linkname: "elsewhere"}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	data := archive.Bytes()
	digest := sha256.Sum256(data)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	originalClient := upgradeHTTPClient
	t.Cleanup(func() { upgradeHTTPClient = originalClient })
	upgradeHTTPClient = srv.Client()
	err := downloadAndInstall(srv.URL, assetName, filepath.Join(t.TempDir(), "nillsec"), digest[:])
	if err == nil || !strings.Contains(err.Error(), "not a regular archive entry") {
		t.Fatalf("downloadAndInstall error = %v; want archive-entry rejection", err)
	}
}

func TestCmdUpgradeMinorVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tar.gz download test not applicable on Windows")
	}

	assetName := upgradeAssetName()
	binaryName := strings.TrimSuffix(assetName, ".tar.gz")
	fakeContent := "#!/bin/sh\necho fake\n"
	tarData := makeFakeTarGz(t, binaryName, fakeContent)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			rel := githubRelease{
				TagName: "v1.3.0",
			}
			rel.Assets = append(rel.Assets, struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
			}{
				Name:               assetName,
				BrowserDownloadURL: srv.URL + "/download/" + assetName,
			})
			rel.Assets = append(rel.Assets, struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
			}{
				Name:               "checksums.txt",
				BrowserDownloadURL: srv.URL + "/download/checksums.txt",
			})
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(rel); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "/checksums.txt") {
			_, _ = fmt.Fprintf(w, "%x  %s\n", sha256.Sum256(tarData), assetName)
			return
		}
		if _, err := w.Write(tarData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	fakeExe := filepath.Join(dir, "nillsec")
	if err := os.WriteFile(fakeExe, []byte("old"), 0o755); err != nil {
		t.Fatalf("writing fake exe: %v", err)
	}

	origVersion := version
	origAPIURL := upgradeAPIURL
	origClient := upgradeHTTPClient
	origExe := executableFn
	t.Cleanup(func() {
		version = origVersion
		upgradeAPIURL = origAPIURL
		upgradeHTTPClient = origClient
		executableFn = origExe
	})

	version = "v1.2.0"
	upgradeAPIURL = srv.URL + "/releases/latest"
	upgradeHTTPClient = srv.Client()
	executableFn = func() (string, error) { return fakeExe, nil }

	if err := cmdUpgrade(); err != nil {
		t.Fatalf("cmdUpgrade (minor): unexpected error: %v", err)
	}

	got, err := os.ReadFile(fakeExe)
	if err != nil {
		t.Fatalf("reading updated exe: %v", err)
	}
	if string(got) != fakeContent {
		t.Errorf("updated binary content = %q; want %q", string(got), fakeContent)
	}
}

func TestCmdUpgradeMajorVersionConfirmed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tar.gz download test not applicable on Windows")
	}

	assetName := upgradeAssetName()
	binaryName := strings.TrimSuffix(assetName, ".tar.gz")
	fakeContent := "#!/bin/sh\necho upgraded\n"
	tarData := makeFakeTarGz(t, binaryName, fakeContent)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			rel := githubRelease{
				TagName: "v2.0.0",
			}
			rel.Assets = append(rel.Assets, struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
			}{
				Name:               assetName,
				BrowserDownloadURL: srv.URL + "/download/" + assetName,
			})
			rel.Assets = append(rel.Assets, struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
			}{
				Name:               "checksums.txt",
				BrowserDownloadURL: srv.URL + "/download/checksums.txt",
			})
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(rel); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "/checksums.txt") {
			_, _ = fmt.Fprintf(w, "%x  %s\n", sha256.Sum256(tarData), assetName)
			return
		}
		if _, err := w.Write(tarData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	fakeExe := filepath.Join(dir, "nillsec")
	if err := os.WriteFile(fakeExe, []byte("old"), 0o755); err != nil {
		t.Fatalf("writing fake exe: %v", err)
	}

	origVersion := version
	origAPIURL := upgradeAPIURL
	origClient := upgradeHTTPClient
	origExe := executableFn
	origStdin := stdinReader
	t.Cleanup(func() {
		version = origVersion
		upgradeAPIURL = origAPIURL
		upgradeHTTPClient = origClient
		executableFn = origExe
		stdinReader = origStdin
	})

	version = "v1.0.0"
	upgradeAPIURL = srv.URL + "/releases/latest"
	upgradeHTTPClient = srv.Client()
	executableFn = func() (string, error) { return fakeExe, nil }
	stdinReader = bufio.NewReader(strings.NewReader("y\n"))

	if err := cmdUpgrade(); err != nil {
		t.Fatalf("cmdUpgrade (major, confirmed): unexpected error: %v", err)
	}

	got, err := os.ReadFile(fakeExe)
	if err != nil {
		t.Fatalf("reading updated exe: %v", err)
	}
	if string(got) != fakeContent {
		t.Errorf("updated binary content = %q; want %q", string(got), fakeContent)
	}
}

func TestDownloadAndInstallPermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission test not applicable on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("test is not meaningful when running as root")
	}

	assetName := upgradeAssetName()
	binaryName := strings.TrimSuffix(assetName, ".tar.gz")
	tarData := makeFakeTarGz(t, binaryName, "#!/bin/sh\necho new\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(tarData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	// Place the fake binary inside a read-only directory so that os.Rename
	// into it fails with a permission error (not a cross-device error).
	dstDir := t.TempDir()
	dstPath := filepath.Join(dstDir, "nillsec")
	if err := os.WriteFile(dstPath, []byte("old"), 0o755); err != nil {
		t.Fatalf("writing old binary: %v", err)
	}
	if err := os.Chmod(dstDir, 0o555); err != nil {
		t.Fatalf("chmod dstDir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dstDir, 0o755) }) //nolint:errcheck

	digest := sha256.Sum256(tarData)
	err := downloadAndInstall(srv.URL+"/download/"+assetName, assetName, dstPath, digest[:])
	if err == nil {
		t.Fatal("downloadAndInstall: expected error for permission-denied destination, got nil")
	}

	// The error should mention elevated privileges and not "check write permissions".
	if strings.Contains(err.Error(), "check write permissions") {
		t.Errorf("downloadAndInstall: error should not mention 'check write permissions', got: %v", err)
	}
	if !strings.Contains(err.Error(), "elevated privileges") {
		t.Errorf("downloadAndInstall: error should mention 'elevated privileges', got: %v", err)
	}

	// The original binary must be untouched.
	got, err2 := os.ReadFile(dstPath)
	if err2 != nil {
		t.Fatalf("reading binary after failed upgrade: %v", err2)
	}
	if string(got) != "old" {
		t.Errorf("binary was modified despite permission error, got: %q", string(got))
	}
}

func TestInstallViaDestDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission test not applicable on Windows")
	}

	content := "#!/bin/sh\necho installed\n"

	// Create source file in a separate temp directory (simulating a download
	// that landed in the system temp directory on a different filesystem).
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, ".nillsec-upgrade-src")
	if err := os.WriteFile(srcPath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	// Create a destination directory with an existing binary.
	dstDir := t.TempDir()
	dstPath := filepath.Join(dstDir, "nillsec")
	if err := os.WriteFile(dstPath, []byte("old"), 0o755); err != nil {
		t.Fatalf("writing old binary: %v", err)
	}

	if err := installViaDestDir(srcPath, dstPath); err != nil {
		t.Fatalf("installViaDestDir: unexpected error: %v", err)
	}

	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("reading installed binary: %v", err)
	}
	if string(got) != content {
		t.Errorf("installed binary content = %q; want %q", string(got), content)
	}

	// Verify executable permission was set.
	info, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("stat installed binary: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("installed binary is not executable (mode %o)", info.Mode())
	}
}
