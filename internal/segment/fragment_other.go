//go:build !linux

package segment

import (
	"context"
)

// fragmentProbe needs a raw IPv4 socket with IP_HDRINCL.
func (t *Tester) fragmentProbe(ctx context.Context, s probeSpec) probeResult {
	return errResult("ip-fragment: " + errUnsupported.Error())
}
