//go:build !unix

package portscan

import "syscall"

// reuseControl is a no-op where SO_REUSEADDR/SO_REUSEPORT are not exposed.
func reuseControl(_, _ string, _ syscall.RawConn) error { return nil }
