// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wait provides a simple mechanism to wait for a value to be set.
package wait

import (
	"context"
	"sync"
)

// Value is a simple mechanism to wait for a value to be set. It's like semaphore, but for values.
//
//nolint:govet
type Value[T any] struct {
	mx    sync.Mutex
	set   chan struct{}
	value T
}

// Set sets the value and unblocks any waiting goroutines.
func (wv *Value[T]) Set(value T) {
	wv.mx.Lock()
	defer wv.mx.Unlock()

	wv.value = value

	if wv.set == nil {
		wv.set = make(chan struct{})
	}

	select {
	case <-wv.set:
	default:
		close(wv.set)
	}
}

// Get waits for the value to be set and returns it. It returns an error if the context is canceled.
func (wv *Value[T]) Get(ctx context.Context) (T, error) {
	wv.mx.Lock()
	if wv.set == nil {
		wv.set = make(chan struct{})
	}

	set := wv.set
	wv.mx.Unlock()

	select {
	case <-ctx.Done():
		return *new(T), ctx.Err()
	case <-set:
	}

	wv.mx.Lock()
	value := wv.value
	wv.mx.Unlock()

	return value, nil
}

// TryGet returns the value if it is set, or false if it is not.
func (wv *Value[T]) TryGet() (T, bool) {
	wv.mx.Lock()
	if wv.set == nil {
		wv.mx.Unlock()

		return *new(T), false
	}

	set := wv.set
	wv.mx.Unlock()

	select {
	case <-set:
		wv.mx.Lock()

		if wv.set == nil {
			wv.mx.Unlock()

			return *new(T), false
		}

		value := wv.value
		wv.mx.Unlock()

		return value, true

	default:
		return *new(T), false
	}
}

// Unset unsets the value. Any Get calls will block until Set is called again.
func (wv *Value[T]) Unset() {
	wv.mx.Lock()
	wv.value = *new(T)
	wv.set = nil
	wv.mx.Unlock()
}
