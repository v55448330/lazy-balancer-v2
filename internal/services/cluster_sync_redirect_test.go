package services

// 3xx 重定向判据必须排除 304 Not Modified（无 Location，不是重定向）。

import (
	"net/http"
	"testing"
)

func TestIsHTTPRedirect_excludesNotModified(t *testing.T) {
	for _, status := range []int{http.StatusMultipleChoices, http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		if !isHTTPRedirect(status) {
			t.Errorf("status %d 应判定为重定向", status)
		}
	}
	for _, status := range []int{http.StatusOK, http.StatusNotModified, http.StatusBadRequest, http.StatusInternalServerError} {
		if isHTTPRedirect(status) {
			t.Errorf("status %d 不应判定为重定向（304 无 Location）", status)
		}
	}
}
