// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package queue

// NewRing creates a new ring buffer with the given size.
func NewRing[T any](size int) *Ring[T] {
	r := &Ring[T]{}
	r.Init(size)

	return r
}

// Ring is a simple ring buffer.
// When `write` does full circle and reaches `read` it will overwrite the oldest data and move the `read` pointer.
type Ring[T any] struct {
	data  []T
	read  int
	write int
	full  bool
}

// Write writes the given data to the ring buffer. If the buffer is full, it will overwrite the oldest data.
// The `read` pointer will be moved to the next position.
func (r *Ring[T]) Write(data T) {
	if r.full {
		r.read = (r.read + 1) % len(r.data)
	}

	r.data[r.write] = data
	r.write = (r.write + 1) % len(r.data)

	if r.write == r.read {
		r.full = true
	}
}

// Read reads the next data from the ring buffer.
// If the buffer is empty, it will return the zero value of the data type and false.
func (r *Ring[T]) Read() (T, bool) {
	if r.read == r.write && !r.full {
		return *new(T), false
	}

	data := r.data[r.read]
	r.read = (r.read + 1) % len(r.data)
	r.full = false

	return data, true
}

// Len returns the number of elements in the ring buffer.
func (r *Ring[T]) Len() int {
	if r.full {
		return len(r.data)
	}

	if r.write >= r.read {
		return r.write - r.read
	}

	return len(r.data) - r.read + r.write
}

// IsFull returns true if the ring buffer is full.
func (r *Ring[T]) IsFull() bool {
	return r.full
}

// Init initializes the ring buffer with the given length. It panics if the buffer is already initialized.
func (r *Ring[T]) Init(size int) {
	if size <= 0 {
		panic("ring: size must be positive")
	}

	if r.data != nil {
		panic("ring: already initialized")
	}

	r.data = make([]T, size)
}
