package types

import "strings"

const DefaultSep = ","

type Rule []string

func (r *Rule) Hash() string {
	return strings.Join(*r, DefaultSep)
}

// Effect is the result for a policy rule.
type Effect int
