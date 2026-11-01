//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	exeSuffix = ""
	ttyPath   = "/dev/tty"
)

var syscallEADDRINUSE error = syscall.EADDRINUSE

var isDarwin = runtime.GOOS == "darwin"

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

// sshRequester describes the ssh command a provider signature is for: our parent is ssh-sk-helper (it loads
// the provider), its parent ssh / ssh-keygen / ssh-add. Walks at most four levels up; falls back to the parent.
func sshRequester() (command, cwd string) {
	pid := strconv.Itoa(os.Getppid())
	for i := 0; i < 4 && pid != "" && pid != "0" && pid != "1"; i++ {
		out, err := exec.Command("ps", "-o", "ppid=,command=", "-p", pid).Output()
		if err != nil {
			break
		}
		ppid, cmd, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
		cmd = strings.TrimSpace(cmd)
		argv0 := filepath.Base(strings.Fields(cmd + " x")[0])
		switch argv0 {
		case "ssh", "ssh-keygen", "ssh-add", "scp", "sftp", "git":
			if out, err := exec.Command("lsof", "-a", "-d", "cwd", "-p", pid, "-Fn").Output(); err == nil {
				for _, l := range strings.Split(string(out), "\n") {
					if strings.HasPrefix(l, "n") {
						cwd = l[1:]
					}
				}
			}
			return clip(cmd), cwd
		}
		pid = strings.TrimSpace(ppid)
	}
	return requester()
}
