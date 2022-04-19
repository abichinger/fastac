package eft

import "example.com/fastac/model/types"

// Values for policy effect.
const (
	Allow types.Effect = iota
	Indeterminate
	Deny
)
