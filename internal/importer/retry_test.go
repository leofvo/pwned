package importer

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCalculateRetryDelay(t *testing.T) {
	t.Parallel()

	base := 100 * time.Millisecond
	max := 1 * time.Second

	cases := []struct {
		name       string
		retryIndex int
		want       time.Duration
	}{
		{name: "first retry", retryIndex: 0, want: 100 * time.Millisecond},
		{name: "second retry", retryIndex: 1, want: 200 * time.Millisecond},
		{name: "third retry", retryIndex: 2, want: 400 * time.Millisecond},
		{name: "capped", retryIndex: 4, want: 1 * time.Second},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := calculateRetryDelay(base, max, tc.retryIndex)
			if got != tc.want {
				t.Fatalf("calculateRetryDelay() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRunWithRetryAndSleepSucceedsAfterRetries(t *testing.T) {
	t.Parallel()

	var (
		callCount  int
		sleepCalls []time.Duration
		retryCalls []int
	)

	policy := retryPolicy{
		MaxRetries: 3,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}

	err := runWithRetryAndSleep(
		context.Background(),
		policy,
		func(_ context.Context, delay time.Duration) error {
			sleepCalls = append(sleepCalls, delay)
			return nil
		},
		func(attempt int, _ time.Duration, _ error) {
			retryCalls = append(retryCalls, attempt)
		},
		func() error {
			callCount++
			if callCount < 3 {
				return errors.New("transient")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("runWithRetryAndSleep() unexpected error: %v", err)
	}

	if callCount != 3 {
		t.Fatalf("operation call count = %d, want 3", callCount)
	}

	wantSleeps := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	if !slices.Equal(sleepCalls, wantSleeps) {
		t.Fatalf("sleep delays = %v, want %v", sleepCalls, wantSleeps)
	}

	wantRetries := []int{1, 2}
	if !slices.Equal(retryCalls, wantRetries) {
		t.Fatalf("retry attempts = %v, want %v", retryCalls, wantRetries)
	}
}

func TestRunWithRetryAndSleepExhaustsRetries(t *testing.T) {
	t.Parallel()

	var (
		callCount  int
		sleepCalls []time.Duration
		retryCalls []int
	)

	policy := retryPolicy{
		MaxRetries: 2,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}

	err := runWithRetryAndSleep(
		context.Background(),
		policy,
		func(_ context.Context, delay time.Duration) error {
			sleepCalls = append(sleepCalls, delay)
			return nil
		},
		func(attempt int, _ time.Duration, _ error) {
			retryCalls = append(retryCalls, attempt)
		},
		func() error {
			callCount++
			return errors.New("permanent")
		},
	)
	if err == nil {
		t.Fatalf("runWithRetryAndSleep() expected error, got nil")
	}

	if callCount != 3 {
		t.Fatalf("operation call count = %d, want 3", callCount)
	}

	wantSleeps := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	if !slices.Equal(sleepCalls, wantSleeps) {
		t.Fatalf("sleep delays = %v, want %v", sleepCalls, wantSleeps)
	}

	wantRetries := []int{1, 2}
	if !slices.Equal(retryCalls, wantRetries) {
		t.Fatalf("retry attempts = %v, want %v", retryCalls, wantRetries)
	}

	if !strings.Contains(err.Error(), "operation failed after 3 attempts") {
		t.Fatalf("error %q does not include expected attempts message", err)
	}
}

func TestRunWithRetryAndSleepInterruptedByContext(t *testing.T) {
	t.Parallel()

	policy := retryPolicy{
		MaxRetries: 3,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}

	err := runWithRetryAndSleep(
		context.Background(),
		policy,
		func(_ context.Context, _ time.Duration) error {
			return context.Canceled
		},
		nil,
		func() error {
			return errors.New("transient")
		},
	)
	if err == nil {
		t.Fatalf("runWithRetryAndSleep() expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
