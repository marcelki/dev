package lock

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	retry = 250 * time.Millisecond

	// Open File Description Locks
	//
	// Usually record locks held by a process are released on *any* close and are
	// not inherited across a fork().
	// These cmd values will set locks that conflict with process-associated
	// record  locks, but are "owned" by the open file description, not the
	// process. This means that they are inherited across fork() like BSD (flock)
	// locks, and they are only released automatically when the last reference to
	// the the open file against which they were acquired is put.
	//
	// source /usr/include/bits/fcntl-linux.h
	F_OFD_GETLK  = 37
	F_OFD_SETLK  = 37
	F_OFD_SETLKW = 38
)

var (
	ErrLockLocked = fmt.Errorf("lock: lock is locked")
)

func NewLocker(path string) *locker {
	return &locker{
		path: path,
	}
}

type locker struct {
	path string
	file *os.File
}

func (l *locker) Lock() error {
	abs, err := filepath.Abs(l.path)
	if err != nil {
		return errors.Wrap(err, "absolute represenation of path failed")
	}
	fi, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Wrap(err, "path doesn't exist")
		}
		return errors.Wrap(err, "stat failed")
	}
	if fi.IsDir() {
		return errors.New("directories are not allowed")
	}
	file, err := os.OpenFile(abs, os.O_RDWR, 0660)
	if err != nil {
		return errors.Wrap(err, "open failed")
	}
	for {
		err = unix.FcntlFlock(file.Fd(), F_OFD_SETLK, &unix.Flock_t{
			Type:   unix.F_WRLCK,
			Whence: int16(io.SeekStart),
		})
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK {
			file.Close()
			return errors.Wrap(err, "lock failed")
		}
		time.Sleep(retry)
	}
	l.path = abs
	l.file = file

	return nil
}

func (l *locker) TryLock() error {
	abs, err := filepath.Abs(l.path)
	if err != nil {
		return errors.Wrap(err, "abs failed")
	}
	fi, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Wrap(err, "path doesn't exist")
		}
		return errors.Wrap(err, "stat failed")
	}
	if fi.IsDir() {
		return errors.New("directories are not allowed")
	}
	file, err := os.OpenFile(abs, os.O_RDWR, 0660)
	if err != nil {
		return errors.Wrap(err, "open failed")
	}
	err = unix.FcntlFlock(file.Fd(), F_OFD_SETLK, &unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: int16(io.SeekStart),
	})
	if err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			err = ErrLockLocked
		}
		return err
	}
	l.path = abs
	l.file = file

	return nil
}

func (l *locker) Unlock() error {
	// it's sufficient to simply close the file descriptor
	if err := l.file.Close(); err != nil {
		return errors.Wrap(err, "close failed")
	}
	return nil
}

// trying to encapsulate the locking method under one function
// considerations:
// - do we still return a file descriptor when a'n error occurs after opening the file
// -- if the locking fails for whatever reason it probably leaks the fd because we don't close it here
func lock(path string) (*os.File, bool, error) {
	var locked bool

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, locked, errors.Wrap(err, "absolute represenation of path failed")
	}
	fi, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, locked, errors.Wrap(err, "path doesn't exist")
		}
		return nil, locked, errors.Wrap(err, "stat failed")
	}
	if fi.IsDir() {
		return nil, locked, errors.New("directories are not allowed")
	}
	file, err := os.OpenFile(abs, os.O_RDWR, 0660)
	if err != nil {
		return nil, locked, errors.Wrap(err, "open failed")
	}
	err = unix.FcntlFlock(file.Fd(), F_OFD_SETLK, &unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: int16(io.SeekStart),
	})
	if err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			locked = true
			return file, locked, nil
		}
		return file, locked, err
	}
	return file, locked, nil
}
