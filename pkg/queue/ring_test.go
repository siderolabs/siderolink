// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package queue_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/siderolink/pkg/queue"
)

func TestRing2(t *testing.T) {
	t.Parallel()

	r := queue.NewRing[int](4)

	expectedValues := []int{2, 3, 4, 5, 6, 7, 14, 15, 16, 17}

	actualValues := make([]int, 0, len(expectedValues))

	for i := range 5 {
		r.Write(i + 1)
	}

	require.True(t, r.IsFull())

	for range r.Len() {
		v, ok := r.Read()
		require.True(t, ok)

		actualValues = append(actualValues, v)
	}

	v, ok := r.Read()
	require.False(t, ok)
	require.Zero(t, v)
	require.Zero(t, r.Len())
	require.False(t, r.IsFull())

	r.Write(6)
	r.Write(7)
	r.Write(8)

	require.Equal(t, 3, r.Len())
	require.False(t, r.IsFull())

	for range 2 {
		v, ok := r.Read()
		require.True(t, ok)

		actualValues = append(actualValues, v)
	}

	for i := range 10 {
		r.Write(i + 8)
	}

	for v, ok := r.Read(); ok; v, ok = r.Read() {
		actualValues = append(actualValues, v)
	}

	require.Equal(t, expectedValues, actualValues)
}

func TestRing(t *testing.T) {
	r := queue.NewRing[int](3)

	expectedValues := []int{3, 4, 5, 6, 7, 15, 16, 17}

	actualValues := make([]int, 0, len(expectedValues))

	for i := range 5 {
		r.Write(i + 1)
	}

	require.True(t, r.IsFull())

	for range r.Len() {
		v, ok := r.Read()
		require.True(t, ok)

		actualValues = append(actualValues, v)
	}

	v, ok := r.Read()
	require.False(t, ok)
	require.Zero(t, v)
	require.Zero(t, r.Len())
	require.False(t, r.IsFull())

	r.Write(6)
	r.Write(7)

	require.Equal(t, 2, r.Len())
	require.False(t, r.IsFull())

	for range 2 {
		v, ok := r.Read()
		require.True(t, ok)

		actualValues = append(actualValues, v)
	}

	require.Zero(t, r.Len())

	for i := range 10 {
		r.Write(i + 8)
	}

	for v, ok := r.Read(); ok; v, ok = r.Read() {
		actualValues = append(actualValues, v)
	}

	require.Equal(t, expectedValues, actualValues)
}
