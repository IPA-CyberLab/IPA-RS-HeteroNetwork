//go:build darwin || linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readSecureConfiguration(path string, expectedFileOwner *uint32) (tunnelConfiguration, uint32, error) {
	var configuration tunnelConfiguration
	fileDescriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return configuration, 0, fmt.Errorf("open configuration: %w", err)
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	if file == nil {
		_ = unix.Close(fileDescriptor)
		return configuration, 0, errors.New("open configuration: invalid file descriptor")
	}
	defer file.Close()

	var status unix.Stat_t
	if err := unix.Fstat(fileDescriptor, &status); err != nil {
		return configuration, 0, fmt.Errorf("inspect configuration: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0o777 != 0o600 || status.Nlink != 1 {
		return configuration, 0, errors.New("configuration must be a single-link regular file with mode 0600")
	}
	fileOwner := status.Uid
	if expectedFileOwner != nil && fileOwner != *expectedFileOwner {
		return configuration, 0, errors.New("configuration file has the wrong owner")
	}
	if status.Size < 2 || status.Size > maximumConfigurationBytes {
		return configuration, 0, errors.New("configuration file has an invalid size")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumConfigurationBytes+1))
	if err != nil {
		return configuration, 0, fmt.Errorf("read configuration: %w", err)
	}
	if len(data) > maximumConfigurationBytes {
		return configuration, 0, errors.New("configuration file is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configuration); err != nil {
		return configuration, 0, fmt.Errorf("decode configuration: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return configuration, 0, errors.New("configuration contains trailing data")
	}
	if err := configuration.validateAndNormalize(); err != nil {
		return configuration, 0, err
	}
	return configuration, fileOwner, nil
}
