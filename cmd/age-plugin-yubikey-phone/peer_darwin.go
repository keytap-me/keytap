package main

import (
	"net"
	"syscall"
)

// peerPID is the process on the other end of a unix socket (LOCAL_PEERPID).
func peerPID(c net.Conn) int {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	raw.Control(func(fd uintptr) {
		pid, _ = syscall.GetsockoptInt(int(fd), 0 /* SOL_LOCAL */, 2 /* LOCAL_PEERPID */)
	})
	return pid
}
