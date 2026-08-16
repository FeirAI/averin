package api

import "testing"

func TestCompletenessGapLine(t *testing.T) {
	tests := []struct {
		name   string
		report string
		want   string
	}{
		{
			name:   "D8 brokered surface",
			report: `{"ok":true,"action_completeness":"attested_complete_over_brokered_surface","resource_trust":"assumed_truthful"}`,
			want:   completenessBrokeredSurface,
		},
		{
			name:   "capstone without overall pass",
			report: `{"ok":false,"action_completeness":"attested_complete_over_brokered_surface","resource_trust":"assumed_truthful"}`,
			want:   completenessNotClaimed,
		},
		{
			name:   "capstone without honest resource bound",
			report: `{"ok":true,"action_completeness":"attested_complete_over_brokered_surface","resource_trust":"verified"}`,
			want:   completenessNotClaimed,
		},
		{
			name:   "manifest claim only",
			report: `{"ok":true,"action_completeness":"claimed_over_manifest","resource_trust":"assumed_truthful"}`,
			want:   completenessNotClaimed,
		},
		{name: "malformed report", report: `{`, want: completenessNotClaimed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := completenessGapLine(tt.report); got != tt.want {
				t.Fatalf("completenessGapLine() = %q, want %q", got, tt.want)
			}
		})
	}
}
