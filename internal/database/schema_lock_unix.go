//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package database

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func lockSQLiteSchema(dbPath string) (func() error, error) {
	lockPath := dbPath + ".schema.lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open SQLite schema lock %s: %w", lockPath, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock SQLite schema %s: %w", dbPath, err)
	}
	return func() error {
		unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
		closeErr := file.Close()
		if unlockErr != nil {
			return fmt.Errorf("unlock SQLite schema %s: %w", dbPath, unlockErr)
		}
		return closeErr
	}, nil
}
