package api

import (
	"context"
	"errors"
	"sync"
)

var (
	errVerifyOverloaded  = errors.New("verification capacity exhausted")
	errVerificationPanic = errors.New("verification failed")
)

// verifyFlightGroup is a single-flight coordinator with cancellation-safe waiters. It is intentionally
// narrower than a general-purpose cache: completed values are removed immediately, because verification
// reports describe a mutable append-only project and a failed report must never be reused as reassurance.
type verifyFlightGroup struct {
	mu         sync.Mutex
	flights    map[string]*verifyFlight
	maxFlights int
}

type verifyFlight struct {
	done      chan struct{}
	report    string
	err       error
	waiters   int
	completed bool
}

func (g *verifyFlightGroup) run(ctx context.Context, key string, work func() (string, error)) (string, error) {
	g.mu.Lock()
	if g.flights == nil {
		g.flights = make(map[string]*verifyFlight)
	}
	flight, exists := g.flights[key]
	leader := !exists
	if leader {
		limit := g.maxFlights
		if limit <= 0 {
			limit = maxConcurrentBundleReads
		}
		if len(g.flights) >= limit {
			g.mu.Unlock()
			return "", errVerifyOverloaded
		}
		flight = &verifyFlight{done: make(chan struct{}), waiters: 1}
		g.flights[key] = flight
	} else {
		flight.waiters++
	}
	g.mu.Unlock()

	if !leader {
		return g.waitForVerifyFlight(ctx, key, flight)
	}

	// Run outside the caller's cancellation context. A browser tab or Telegram retry may disappear while
	// Rust/cgo is still verifying; the shared work must complete for any remaining waiters and must not leave a
	// partially published result behind.
	go func() {
		report, err := runVerifyWork(work)
		g.mu.Lock()
		flight.report = report
		flight.err = err
		flight.completed = true
		close(flight.done)
		if flight.waiters == 0 {
			delete(g.flights, key)
		}
		g.mu.Unlock()
	}()
	return g.waitForVerifyFlight(ctx, key, flight)
}

func (g *verifyFlightGroup) waitForVerifyFlight(ctx context.Context, key string, flight *verifyFlight) (string, error) {
	var report string
	var err error
	select {
	case <-flight.done:
		report, err = flight.report, flight.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	g.mu.Lock()
	flight.waiters--
	if flight.completed && flight.waiters == 0 {
		delete(g.flights, key)
	}
	g.mu.Unlock()
	return report, err
}

func runVerifyWork(work func() (string, error)) (report string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			report = ""
			err = errVerificationPanic
		}
	}()
	return work()
}
