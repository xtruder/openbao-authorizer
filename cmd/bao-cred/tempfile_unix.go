//go:build !windows

package main

import "os"

func createSecureTemp(directory string) (*os.File, error) {
	file, err := os.CreateTemp(directory, ".bao-cred-*")
	if err != nil {
		return nil, err
	}

	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}

	return file, nil
}
