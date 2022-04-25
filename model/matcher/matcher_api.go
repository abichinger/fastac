package matcher

import (
	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/fm"
	"github.com/abichinger/fastac/model/kind"
)

type IMatcher interface {
	GetPolicyKey() string
	RangeMatches(rDef defs.RequestDef, rvals []interface{}, fMap fm.FunctionMap, fn func(rule kind.Rule) bool) error
}
