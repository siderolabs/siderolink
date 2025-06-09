// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package queue_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/siderolink/pkg/queue"
)

func TestQueue(t *testing.T) {
	t.Parallel()

	q := queue.NewRingQueue[int](3)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	err := q.Push(ctx, 1)
	require.NoError(t, err)

	v, err := q.Pop(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, v)

	for i := range 10 {
		err := q.Push(ctx, i) //nolint:govet
		require.NoError(t, err)
	}

	for i := range 3 {
		v, err := q.Pop(ctx) //nolint:govet
		require.NoError(t, err)
		require.Equal(t, i+7, v)
	}

	cancel()

	err = q.Push(ctx, 1)
	require.EqualError(t, err, "context canceled")

	v, err = q.Pop(ctx)
	require.EqualError(t, err, "context canceled")
	require.Zero(t, v)
}
