package fm

import "github.com/abichinger/govaluate"

var globalFns *FunctionMap

func getGlobalFunctionMap() *FunctionMap {
	if globalFns == nil {
		globalFns = NewFunctionMap()
	}
	return globalFns
}

func SetFunction(name string, function govaluate.ExpressionFunction) {
	getGlobalFunctionMap().SetFunction(name, function)
}
