package importer

import (
	"context"
	"fmt"
	"time"
)

type retryPolicy struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
}

func runWithRetry(
	ctx context.Context,
	policy retryPolicy,
	onRetry func(attempt int, delay time.Duration, err error),
	operation func() error,
) error {
	return runWithRetryAndSleep(ctx, policy, sleepWithContext, onRetry, operation)
}

func runWithRetryAndSleep(
	ctx context.Context,
	policy retryPolicy,
	sleepFn func(context.Context, time.Duration) error,
	onRetry func(attempt int, delay time.Duration, err error),
	operation func() error,
) error {
	if policy.MaxRetries < 0 {
		policy.MaxRetries = 0
	}
	if policy.BaseDelay <= 0 {
		policy.BaseDelay = 100 * time.Millisecond
	}
	if policy.MaxDelay < policy.BaseDelay {
		policy.MaxDelay = policy.BaseDelay
	}

	var lastErr error
	maxAttempts := policy.MaxRetries + 1
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return fmt.Errorf("%w (previous error: %v)", err, lastErr)
			}
			return err
		}

		err := operation()
		if err == nil {
			return nil
		}
		lastErr = err

		if attempt == policy.MaxRetries {
			break
		}

		delay := calculateRetryDelay(policy.BaseDelay, policy.MaxDelay, attempt)
		if onRetry != nil {
			onRetry(attempt+1, delay, err)
		}

		if err := sleepFn(ctx, delay); err != nil {
			return fmt.Errorf("retry wait interrupted: %w", err)
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, lastErr)
}

func calculateRetryDelay(base time.Duration, max time.Duration, retryIndex int) time.Duration {
	delay := base
	for i := 0; i < retryIndex; i++ {
		if delay >= max {
			return max
		}
		next := delay * 2
		if next <= 0 || next > max {
			return max
		}
		delay = next
	}
	if delay > max {
		return max
	}
	return delay
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
