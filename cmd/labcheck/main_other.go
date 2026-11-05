//go:build !linux

// labcheck creates 802.1Q sub-interfaces, assigns addresses and installs routes
// through netlink. None of that exists off Linux, so rather than leave the package
// unbuildable there, it builds into something that says so and exits. Without this the
// cross-compilation check in CI fails on a tool that was never meant to run on the
// platform it was being built for.
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr,
		"labcheck only runs on Linux: it drives netlink, which %s does not have.\n",
		runtime.GOOS)
	os.Exit(1)
}
