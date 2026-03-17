package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
		{"1.0.0", 1, false},  // without 'v' prefix
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
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(rel); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
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
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(rel); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
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
