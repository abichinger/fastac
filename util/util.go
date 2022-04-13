package util

import (
	"regexp"
	"sort"
)

var evalReg *regexp.Regexp = regexp.MustCompile(`\beval\((?P<rule>[^)]*)\)`)

// HasEval determine whether matcher contains function eval
func HasEval(s string) bool {
	return evalReg.MatchString(s)
}

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
