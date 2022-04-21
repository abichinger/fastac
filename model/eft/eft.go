package eft

import "github.com/abichinger/fastac/model/types"

// Values for policy effect.
const (
	Allow types.Effect = iota
	Indeterminate
	Deny
)
