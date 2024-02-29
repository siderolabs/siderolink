// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wait_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/siderolink/internal/wait"
)

func TestWaitableValue(t *testing.T) {
	t.Parallel()

	var wv wait.Value[int]

	_, ok := wv.TryGet()
	require.False(t, ok)

	wv.Set(41)
	wv.Set(42) // Ensure that the last value is the one that sticks.

	value, ok := wv.TryGet()
	require.True(t, ok)
	require.Equal(t, 42, value)

	value, err := wv.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, 42, value)

	wv.Unset()

	value, ok = wv.TryGet()
	require.False(t, ok)
	require.Equal(t, 0, value)
}

func TestParallel(t *testing.T) { //nolint:tparallel
	t.Parallel()

	var wv wait.Value[int]

	t.Run("GetSet", func(t *testing.T) {
		t.Run("Set", func(t *testing.T) {
			t.Parallel()

			time.Sleep(time.Millisecond) // Just to make sure the other goroutine is waiting.

			wv.Set(42)
		})

		t.Run("Get", func(t *testing.T) {
			t.Parallel()

			val, err := wv.Get(context.Background())

			require.NoError(t, err)
			require.Equal(t, 42, val)
		})
	})

	wv.Unset()

	t.Run("GetNotSet", func(t *testing.T) {
		t.Run("Get", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()

			val, err := wv.Get(ctx)
			require.EqualError(t, err, "context deadline exceeded")
			require.Equal(t, 0, val)
		})

		t.Run("TryGet", func(t *testing.T) {
			t.Parallel()

			time.Sleep(time.Millisecond) // Just to make sure the other goroutine is done with get.

			val, ok := wv.TryGet()
			require.False(t, ok)
			require.Equal(t, 0, val)
		})
	})
}
