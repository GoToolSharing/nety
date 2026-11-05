package store

import (
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// A scan killed while its phases were being written finished without doing the work it
// was asked for. It has to be offered again rather than read as done.
func TestACompletedScanWithAnUnfinishedPlanIsResumable(t *testing.T) {
	cases := []struct {
		name   string
		status model.ScanStatus
		phases []model.PhaseProgress
		want   bool
	}{
		{
			name:   "completed with only the L2 phase",
			status: model.ScanCompleted,
			phases: []model.PhaseProgress{{Phase: model.PhaseL2, Total: 1, Done: 1}},
			want:   true,
		},
		{
			name:   "completed with no phase at all",
			status: model.ScanCompleted,
			want:   true,
		},
		{
			name:   "a genuinely finished discovery scan",
			status: model.ScanCompleted,
			phases: []model.PhaseProgress{
				{Phase: model.PhaseL2, Total: 1, Done: 1},
				{Phase: model.PhaseDiscovery, Total: 4, Done: 4},
			},
			want: false,
		},
		{
			name:   "a genuinely finished segmentation scan",
			status: model.ScanCompleted,
			phases: []model.PhaseProgress{{Phase: model.PhaseSegment, Total: 9, Done: 9}},
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resumable(model.Scan{Status: tc.status, Phases: tc.phases})
			if got != tc.want {
				t.Fatalf("resumable = %v, want %v", got, tc.want)
			}
		})
	}
}
