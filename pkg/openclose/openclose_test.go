// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package openclose_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/siderolink/pkg/openclose"
)

func TestOpenClose(t *testing.T) {
	t.Parallel()

	t.Run("normal", func(t *testing.T) {
		t.Parallel()

		closed := make(chan struct{})

		oc := &openclose.OpenClose{}
		ok, closeFn := oc.Open(nil)
		require.True(t, ok)

		t.Run("open", func(t *testing.T) {
			t.Parallel()

			defer close(closed)

			ok, _ := oc.Open(nil)
			require.False(t, ok)

			for !oc.IsCloseRequested() { //nolint:revive
			}

			closeFn()
			closeFn()

			for !oc.IsClosed() { //nolint:revive
			}
		})

		t.Run("close", func(t *testing.T) {
			t.Parallel()

			oc.RequestCloseWait(nil)
			<-closed
		})
	})

	t.Run("close before open", func(t *testing.T) {
		t.Parallel()

		oc := &openclose.OpenClose{}
		ok := oc.RequestCloseWait(nil)
		require.False(t, ok)

		ok, _ = oc.Open(nil)
		require.False(t, ok)
	})

	t.Run("close fn should happen even if open was not called", func(t *testing.T) {
		t.Parallel()

		ch := make(chan struct{})

		oc := &openclose.OpenClose{}
		ok := oc.RequestClose(func() {
			close(ch)
		})
		require.False(t, ok)

		ok, _ = oc.Open(func() {
			close(ch)
		})
		require.False(t, ok)
	})

	t.Run("should report closed", func(t *testing.T) {
		t.Parallel()

		oc := &openclose.OpenClose{}
		ok, closeFn := oc.Open(nil)
		require.True(t, ok)
		require.False(t, oc.IsClosed())

		t.Run("runner 1", func(t *testing.T) {
			t.Parallel()

			closeFn()
		})

		t.Run("runner 2", func(t *testing.T) {
			t.Parallel()

			for !oc.IsClosed() { //nolint:revive
			}
		})
	})
}
