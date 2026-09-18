//go:build darwin || linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureConfigurationRequiresOwnerOnlyRegularFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tunnel.json")
	data, err := json.Marshal(validTestConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	configuration, owner, err := readSecureConfiguration(path, &uid)
	if err != nil {
		t.Fatalf("secure configuration rejected: %v", err)
	}
	if owner != uid || configuration.OwnerUID != 501 {
		t.Fatalf("unexpected owners: file=%d configuration=%d", owner, configuration.OwnerUID)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSecureConfiguration(path, &uid); err == nil {
		t.Fatal("group-readable configuration was accepted")
	}
}

func TestSecureConfigurationRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	link := filepath.Join(directory, "link.json")
	data, err := json.Marshal(validTestConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	if _, _, err := readSecureConfiguration(link, &uid); err == nil {
		t.Fatal("linked configuration was accepted")
	}
}
