// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package queue

import "context"

// NewRingQueue creates a new ring queue with the given size.
func NewRingQueue[T any](size int) *RingQueue[T] {
	q := &RingQueue[T]{
		nonEmpty: make(chan struct{}, 1),
		empty:    make(chan struct{}, 1),
	}

	q.r.Init(size)

	q.empty <- struct{}{}

	return q
}

// RingQueue is a thread-safe ring queue.
type RingQueue[T any] struct {
	nonEmpty chan struct{}
	empty    chan struct{}
	r        Ring[T]
}

// Push pushes a value to the queue. It blocks until the value is pushed (likely) or the context is canceled.
func (q *RingQueue[T]) Push(ctx context.Context, v T) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	select {
	case <-q.empty:
	case <-q.nonEmpty:
	case <-ctx.Done():
		return ctx.Err()
	}

	q.r.Write(v)
	q.nonEmpty <- struct{}{}

	return nil
}

// Pop pops a value from the queue. It blocks until the value is popped or the context is canceled.
func (q *RingQueue[T]) Pop(ctx context.Context) (T, error) {
	select {
	case <-ctx.Done():
		return *new(T), ctx.Err()
	default:
	}

	select {
	case <-q.nonEmpty:
	case <-ctx.Done():
		return *new(T), ctx.Err()
	}

	v, _ := q.r.Read()

	if q.r.Len() == 0 {
		q.empty <- struct{}{}
	} else {
		q.nonEmpty <- struct{}{}
	}

	return v, nil
}
