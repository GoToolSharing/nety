//go:build !linux

package rawnet

// CanRaw is always false off Linux: AF_PACKET sockets do not exist there, so engines fall
// back to connect-mode scanning and unprivileged ICMP/UDP.
func CanRaw() bool { return false }
