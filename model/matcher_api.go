package model

type IMatcher interface {
	RangeMatches(rDef RequestDef, rvals []interface{}, fm FunctionMap, fn func(rule Rule) bool) error
}
