package store

import (
	"os"
	"path/filepath"
)

// syncFile flushes a file's contents and metadata.
func syncFile(f *os.File) error {
	return f.Sync()
}

// syncDir flushes the directory entry that names a file. A rename or
// create is not durable until the parent directory itself is synced.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	cerr := d.Close()
	if err != nil {
		return err
	}
	return cerr
}

func dirOf(path string) string {
	return filepath.Dir(path)
}
