package services

import "testing"

func TestCustomRulePattern_rejectsEmptyAlternative(t *testing.T) {
	cases := []struct {
		pattern string
		wantErr bool
	}{
		{pattern: `(?i)(PHP_SESSION_UPLOAD_PROGRESS||p2s-rider)`, wantErr: true},
		{pattern: `(?i)(PHP_SESSION_UPLOAD_PROGRESS|p2s-rider)`, wantErr: false},
		{pattern: `foo\|\|bar`, wantErr: false},
		{pattern: `[||]`, wantErr: false},
		{pattern: `foo|bar`, wantErr: false},
		{pattern: `foo||bar`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			err := validateCustomRulePattern("regex", tc.pattern)
			if (err != nil) != tc.wantErr {
				t.Fatalf("pattern=%q err=%v wantErr=%v", tc.pattern, err, tc.wantErr)
			}
		})
	}
}
