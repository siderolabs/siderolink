// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package queue provides a thread-safe queue and ring-queue.
package queue

import "context"

// New creates a new queue with the given size.
func New[T any](size int) Queue[T] {
	return Queue[T]{
		ch: make(chan T, size),
	}
}

// Queue is a thread-safe queue.
type Queue[T any] struct {
	ch chan T
}

// Push pushes a value to the queue. It blocks until the value is pushed or the context is canceled.
func (q *Queue[T]) Push(ctx context.Context, v T) error {
	select {
	case q.ch <- v:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Pop pops a value from the queue. It blocks until the value is popped or the context is canceled.
func (q *Queue[T]) Pop(ctx context.Context) (T, error) {
	select {
	case v := <-q.ch:
		return v, nil
	case <-ctx.Done():
		return *new(T), ctx.Err()
	}
}
