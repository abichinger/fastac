package model

import (
	"example.com/lessbin/util"
	"github.com/Knetic/govaluate"
)

type FunctionMap struct {
	fns map[string]govaluate.ExpressionFunction
}

func DefaultFunctionMap() *FunctionMap {
	fm := &FunctionMap{}
	fm.fns = make(map[string]govaluate.ExpressionFunction)

	fm.AddFunction("keyMatch", util.KeyMatchFunc)
	fm.AddFunction("keyGet", util.KeyGetFunc)
	fm.AddFunction("keyMatch2", util.KeyMatch2Func)
	fm.AddFunction("keyGet2", util.KeyGet2Func)
	fm.AddFunction("keyMatch3", util.KeyMatch3Func)
	fm.AddFunction("keyMatch4", util.KeyMatch4Func)
	fm.AddFunction("keyMatch5", util.KeyMatch5Func)
	fm.AddFunction("regexMatch", util.RegexMatchFunc)
	fm.AddFunction("ipMatch", util.IPMatchFunc)
	fm.AddFunction("globMatch", util.GlobMatchFunc)

	return fm
}

func (fm *FunctionMap) AddFunction(name string, function govaluate.ExpressionFunction) {
	fm.fns[name] = function
}

func (fm *FunctionMap) RemoveFunction(name string) bool {
	_, ok := fm.fns[name]
	delete(fm.fns, name)
	return ok
}

// GetFunctions return a map with all the functions
func (fm *FunctionMap) GetFunctions() map[string]govaluate.ExpressionFunction {
	return fm.fns
}
