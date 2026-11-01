//go:build !darwin && !linux

package main

import "net"

func peerPID(net.Conn) int { return 0 }
