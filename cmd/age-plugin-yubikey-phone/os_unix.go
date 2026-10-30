//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const (
	exeSuffix = ""
	ttyPath   = "/dev/tty"
)

var syscallEADDRINUSE error = syscall.EADDRINUSE

// runReal replaces this process with the real plugin: same pid, same stdio, nothing in between.
func runReal(path string, args []string) error {
	return syscall.Exec(path, append([]string{"age-plugin-yubikey"}, args...), os.Environ())
}

// requester describes the process that asked for the decrypt: our parent is sops or age (a relay
// shim execs us in place, so it does not appear in between).
func requester() (command, cwd string) {
	ppid := strconv.Itoa(os.Getppid())
	if out, err := exec.Command("ps", "-o", "command=", "-p", ppid).Output(); err == nil {
		command = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("lsof", "-a", "-d", "cwd", "-p", ppid, "-Fn").Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, "n") {
				cwd = l[1:]
			}
		}
	}
	return clip(command), cwd
}
