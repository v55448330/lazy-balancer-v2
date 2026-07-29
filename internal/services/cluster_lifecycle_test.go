package services

import (
	"context"
	"testing"
)

func TestRuntimeLifecycle_StopACME_waits_before_starting_next_generation(t *testing.T) {
	// Given
	firstStarted := make(chan struct{})
	firstCanceled := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	generation := 0
	lifecycle := NewRuntimeLifecycle(nil, func() *CertificateService {
		generation++
		service := NewCertificateService()
		if generation == 1 {
			service.recoverJobs = func(ctx context.Context) {
				close(firstStarted)
				<-ctx.Done()
				close(firstCanceled)
				<-releaseFirst
			}
		} else {
			service.recoverJobs = func(ctx context.Context) {
				close(secondStarted)
				<-ctx.Done()
			}
		}
		return service
	})
	lifecycle.StartACME()
	<-firstStarted
	stopDone := make(chan struct{})
	go func() {
		lifecycle.StopACME()
		close(stopDone)
	}()
	<-firstCanceled
	startDone := make(chan struct{})
	go func() {
		lifecycle.StartACME()
		close(startDone)
	}()

	// When
	select {
	case <-startDone:
		t.Fatal("next ACME generation started before the previous generation exited")
	default:
	}
	close(releaseFirst)

	// Then
	<-stopDone
	<-startDone
	<-secondStarted
	lifecycle.StopACME()
}
