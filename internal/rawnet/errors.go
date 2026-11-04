package rawnet

import "github.com/GoToolSharing/nety/internal/engine"

// ErrUnsupported and ErrNeedPrivileges are re-exported from package engine so
// callers can test rawnet failures with errors.Is against either package.
var (
	ErrUnsupported    = engine.ErrUnsupported
	ErrNeedPrivileges = engine.ErrNeedPrivileges
)
