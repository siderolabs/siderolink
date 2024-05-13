// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package iter provides utilities for working with iterators.
package iter

// Seq is a sequence of elements.
type Seq[T any] func(yield func(T) bool)

// Deduplicate yields elements from elems, skipping duplicates. It always yields the last equal element.
// The equal function is used to compare elements.
// The yield function is used to yield elements. If it returns false, the iteration stops.
// Slice should be sorted before calling this function.
func Deduplicate[T any](elems []T, equal func(a, b T) bool) Seq[T] {
	return func(yield func(T) bool) {
		switch len(elems) {
		case 1:
			yield(elems[0])

			fallthrough
		case 0:
			return
		}

		last := elems[0]
		for _, elem := range elems[1:] {
			if equal(last, elem) {
				last = elem

				continue
			}

			if !yield(last) {
				return
			}

			last = elem
		}

		yield(last)
	}
}

// Filter iterates over elements in seq, calling the given function for each element.
// If the function returns true, the element is yielded.
func Filter[T any](seq Seq[T], fn func(T) bool) Seq[T] {
	return func(yield func(T) bool) {
		seq(func(elem T) bool {
			if fn(elem) {
				return yield(elem)
			}

			return true
		})
	}
}
