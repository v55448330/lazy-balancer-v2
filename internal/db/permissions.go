package db

import (
	"errors"
	"fmt"
	"os"
)

const (
	dataDirectoryMode os.FileMode = 0700
	databaseFileMode  os.FileMode = 0600
)

func secureDataDirectory(path string) error {
	if err := os.MkdirAll(path, dataDirectoryMode); err != nil {
		return err
	}
	return os.Chmod(path, dataDirectoryMode)
}

func prepareSQLiteDatabase(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, databaseFileMode)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return secureSQLiteArtifacts(path)
}

func secureSQLiteArtifacts(path string) error {
	for _, artifact := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(artifact, databaseFileMode); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("chmod %s: %w", artifact, err)
		}
	}
	return nil
}
