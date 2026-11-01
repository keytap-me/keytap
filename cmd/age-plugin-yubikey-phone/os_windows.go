//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	exeSuffix = ".exe"
	ttyPath   = "CONOUT$" // the console, even when stderr is captured by sops
)

// WSAEADDRINUSE: Windows reports a taken port with the Winsock code, not the POSIX one.
var syscallEADDRINUSE error = syscall.Errno(10048)

// runReal runs the real plugin as a child with this process's stdio (Windows has no exec) and
// exits with its status.
func runReal(path string, args []string) error {
	cmd := exec.Command(path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	if err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

// requester asks Windows for the parent's command line (sops or age). The working directory of
// another process is not available without native APIs, so it stays empty.
func requester() (command, cwd string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := "(Get-CimInstance Win32_Process -Filter 'ProcessId=" + strconv.Itoa(os.Getppid()) + "').CommandLine"
	if out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", q).Output(); err == nil {
		command = strings.TrimSpace(string(out))
	}
	return clip(command), ""
}

var isDarwin = false

func sshRequester() (command, cwd string) { return requester() }
