// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package iter_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/siderolink/pkg/iter"
)

func TestDeduplicate(t *testing.T) {
	type elem struct { //nolint:govet
		value int
		name  string
	}

	tests := map[string]struct {
		elems    []elem
		expected []string
	}{
		"empty": {},
		"single": {
			elems: []elem{
				{1, "a"},
			},
			expected: []string{"a"},
		},
		"multiple equal": {
			elems: []elem{
				{1, "a"},
				{1, "b"},
				{1, "c"},
			},
			expected: []string{"c"},
		},
		"two different": {
			elems: []elem{
				{1, "a"},
				{1, "b"},
				{1, "c"},
				{2, "d"},
				{2, "e"},
				{2, "f"},
			},
			expected: []string{"c", "f"},
		},
		"three different": {
			elems: []elem{
				{1, "a"},
				{2, "d"},
				{2, "e"},
				{2, "f"},
				{3, "g"},
			},
			expected: []string{"a", "f", "g"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			it := iter.Deduplicate(test.elems, func(a, b elem) bool { return a.value == b.value })

			var result []string

			it(func(elem elem) bool {
				result = append(result, elem.name)

				return true
			})

			require.Equal(t, test.expected, result)
		})
	}
}
