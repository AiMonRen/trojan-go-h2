//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package database

import "sync"

var sqliteSchemaLocks sync.Map

func lockSQLiteSchema(dbPath string) (func() error, error) {
	value, _ := sqliteSchemaLocks.LoadOrStore(dbPath, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	return func() error {
		lock.Unlock()
		return nil
	}, nil
}
