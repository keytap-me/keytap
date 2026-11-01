//go:build !windows

package main

import (
	"errors"
	"net"
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

func processAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// detach starts the holder in its own session, so it outlives the plugin invocation and the terminal.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

func parentOf(pid string) (ppid, command string) {
	out, err := exec.Command("ps", "-o", "ppid=,command=", "-p", pid).Output()
	if err != nil {
		return "", ""
	}
	p, cmd, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	return strings.TrimSpace(p), strings.TrimSpace(cmd)
}

// askingPID is the process that asked for the decrypt: our parent (sops or age), skipping a wrapper that
// itself answers to the plugin name (a race router script in front of us).
func askingPID() string {
	pid := strconv.Itoa(os.Getppid())
	for i := 0; i < 3; i++ {
		ppid, cmd := parentOf(pid)
		if ppid == "" || !strings.Contains(cmd, "age-plugin-yubikey") {
			break
		}
		pid = ppid
	}
	return pid
}

// sshPID is the ssh (ssh-keygen, ssh-add …) process a provider signature is for — the session key of sk-sign:
// ssh starts a new ssh-sk-helper for every identity it tries.
func sshPID() int {
	pid := strconv.Itoa(os.Getppid())
	for i := 0; i < 4 && pid != "" && pid != "0" && pid != "1"; i++ {
		ppid, cmd := parentOf(pid)
		argv0 := filepath.Base(strings.Fields(cmd + " x")[0])
		switch argv0 {
		case "ssh", "ssh-keygen", "ssh-add", "scp", "sftp", "git":
			n, _ := strconv.Atoi(pid)
			return n
		}
		pid = ppid
	}
	return os.Getppid()
}

// requester describes the process that asked for the decrypt: sops or age (a relay shim execs us in
// place, so it does not appear in between; a router script is skipped).
func requester() (command, cwd string) {
	ppid := askingPID()
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

// agentPeer describes the ssh command on the other end of an agent connection.
func agentPeer(c net.Conn) (command, cwd string) {
	pid := peerPID(c)
	if pid <= 0 {
		return "ssh (through the KeyTap agent)", ""
	}
	p := strconv.Itoa(pid)
	_, command = parentOf(p)
	if out, err := exec.Command("lsof", "-a", "-d", "cwd", "-p", p, "-Fn").Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, "n") {
				cwd = l[1:]
			}
		}
	}
	if command == "" {
		command = "ssh (through the KeyTap agent)"
	}
	return clip(command), cwd
}
