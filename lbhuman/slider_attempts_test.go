package lbhuman

import "testing"

// F3（安全评审）：失败 3 次强制换图——第 3 次尝试必须仍可校验，
// 此前先自增后 >=3 判删让第 3 次在校验前被强制失效（实际只有 2 次可用）。
func TestConsumeSliderPuzzle_thirdAttemptVerifiable(t *testing.T) {
	sliderPuzzlesMu.Lock()
	sliderPuzzles = map[string]*sliderPuzzle{}
	sliderPuzzlesMu.Unlock()
	p := newSliderPuzzle()

	for attempt := 1; attempt <= sliderMaxAttempts; attempt++ {
		got := consumeSliderPuzzle(p.id)
		if got == nil {
			t.Fatalf("第 %d 次尝试（上限 %d）必须仍可校验，却被提前强制失效", attempt, sliderMaxAttempts)
		}
	}
	// 超过上限的第 4 次才强制失效换新。
	if got := consumeSliderPuzzle(p.id); got != nil {
		t.Fatal("超过尝试上限后必须强制失效")
	}
}
