package util

import (
	"sort"
)

// SetEquals determines whether two string sets are identical.
func SetEqualsInt(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	sort.Ints(a)
	sort.Ints(b)

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
