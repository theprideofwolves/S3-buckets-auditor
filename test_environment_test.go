package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Direct `go test` must be safe even when the developer has signed in to AWS.
// Fake SDK tests explicitly replace this closed endpoint and use synthetic keys.
func TestMain(m *testing.M) {
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "AWS_") || strings.HasPrefix(upper, "JIRA_") || strings.HasPrefix(upper, "S3_AUDITOR_") {
			os.Unsetenv(name)
		}
	}
	dir, err := os.MkdirTemp("", "s3-tests-")
	if err != nil {
		os.Stderr.WriteString("cannot create isolated test directory\n")
		os.Exit(1)
	}
	empty := filepath.Join(dir, "empty-config")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		os.RemoveAll(dir)
		os.Stderr.WriteString("cannot isolate AWS configuration\n")
		os.Exit(1)
	}
	for key, value := range map[string]string{
		"AWS_CONFIG_FILE": empty, "AWS_SHARED_CREDENTIALS_FILE": empty,
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_ENDPOINT_URL": "http://127.0.0.1:1", "AWS_MAX_ATTEMPTS": "1",
		"S3_AUDITOR_DATA_DIR": filepath.Join(dir, "data"), "S3_AUDITOR_NO_BROWSER": "1",
	} {
		if err := os.Setenv(key, value); err != nil {
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
