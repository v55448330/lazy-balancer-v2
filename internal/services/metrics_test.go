package services

import "testing"

func TestClassifyStatusCodes_uses_complete_numeric_ranges(t *testing.T) {
	// Given
	codes := map[int]int64{
		199: 1,
		200: 2,
		299: 3,
		300: 4,
		399: 5,
		400: 6,
		499: 7,
		500: 8,
		599: 9,
		600: 10,
	}

	// When
	counts := classifyStatusCodes(codes)

	// Then
	if counts.status2xx != 5 || counts.status3xx != 9 || counts.status4xx != 13 || counts.status5xx != 17 || counts.other != 11 {
		t.Fatalf("classified counts=%+v", counts)
	}
}
