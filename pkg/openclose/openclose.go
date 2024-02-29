// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package openclose provides a synchronization primitive (similar to a semaphore)
package openclose

import "sync"

// OpenClose represents a synchronization primitive (similar to a semaphore)
// that can be used to signal that an operation has started.
// All methods are safe to call from multiple goroutines.
type OpenClose struct {
	cnd            *sync.Cond
	mx             sync.Mutex
	opened         bool
	closed         bool
	closeRequested bool
}

// Open opens the OpenClose and returns a function that can be used to close it.
// If the OpenClose is already opened or closed, it returns false and a nil function.
// If fn is not nil, it will be called before the OpenClose is opened.
func (oc *OpenClose) Open(fn func()) (bool, func()) {
	oc.mx.Lock()
	defer oc.mx.Unlock()

	if oc.opened {
		return false, nil
	}

	if oc.closed {
		return false, nil
	}

	if fn != nil {
		fn()
	}

	oc.opened = true
	oc.cnd = sync.NewCond(&oc.mx)

	return true, oc.close
}

func (oc *OpenClose) close() {
	oc.mx.Lock()
	defer oc.mx.Unlock()

	if oc.closed {
		return
	}

	oc.closed = true
	oc.cnd.Broadcast()
}

// RequestClose requests that the OpenClose be closed and calls fn if close has not been requested.
// It will run fn even if the OpenClose is already closed from Open callback, but it was not requested to be closed.
func (oc *OpenClose) RequestClose(fn func()) bool {
	oc.mx.Lock()
	defer oc.mx.Unlock()

	return oc.requestClose(fn)
}

// RequestCloseWait requests that the OpenClose be closed and calls fn if close has not been requested.
// It will run fn even if the OpenClose is already closed from Open callback, but it was not requested to be closed.
// It waits until the Open callback is called and the OpenClose is closed.
func (oc *OpenClose) RequestCloseWait(fn func()) bool {
	oc.mx.Lock()
	defer oc.mx.Unlock()

	if !oc.requestClose(fn) {
		return false
	}

	for !oc.closed {
		oc.cnd.Wait()
	}

	return true
}

func (oc *OpenClose) requestClose(fn func()) bool {
	if !oc.closeRequested {
		if fn != nil {
			fn()
		}

		oc.closeRequested = true
	}

	if !oc.opened {
		oc.closed = true

		return false
	}

	return true
}

// IsClosed returns true if the OpenClose is closed.
func (oc *OpenClose) IsClosed() bool {
	oc.mx.Lock()
	defer oc.mx.Unlock()

	return oc.closed
}

// IsCloseRequested returns true if the OpenClose is requested to be closed.
func (oc *OpenClose) IsCloseRequested() bool {
	oc.mx.Lock()
	defer oc.mx.Unlock()

	return oc.closeRequested
}
