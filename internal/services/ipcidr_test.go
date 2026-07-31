package services

import (
	"reflect"
	"testing"
)

func TestNormalizeCIDRsAcceptsBareIPs(t *testing.T) {
	got, err := NormalizeCIDRs([]string{"192.168.1.5", "2001:db8::1", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.5/32", "2001:db8::1/128", "10.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeCIDRs()=%v, want %v", got, want)
	}
}

func TestNormalizeCIDRsRejectsInvalidCIDR(t *testing.T) {
	if _, err := NormalizeCIDRs([]string{"not-an-ip"}); err == nil {
		t.Fatal("NormalizeCIDRs() error=nil, want validation error")
	}
}
