// Copyright 2022 The FastAC Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fm

import (
	"github.com/abichinger/fastac/util"
	"github.com/abichinger/govaluate"
)

type FunctionMap struct {
	fns map[string]govaluate.ExpressionFunction
}

//NewFunctionMap returns an empty function map
func NewFunctionMap() *FunctionMap {
	fm := &FunctionMap{}
	fm.fns = make(map[string]govaluate.ExpressionFunction)
	return fm
}

//DefaultFunctionMap returns a function map with all global registered functions and the built in functions (pathMatch, regexMatch, ...)
func DefaultFunctionMap() *FunctionMap {
	fm := NewFunctionMap()

	fm.SetFunction("eval", func(arguments ...interface{}) (interface{}, error) { return nil, nil })
	fm.SetFunction("pathMatch", util.PathMatchFunc)
	fm.SetFunction("pathMatch2", util.PathMatchFunc2)
	fm.SetFunction("regexMatch", util.RegexMatchFunc)
	fm.SetFunction("ipMatch", util.IPMatchFunc)
	fm.SetFunction("globMatch", util.GlobMatchFunc)

	global := getGlobalFunctionMap()
	for name, fn := range global.fns {
		fm.SetFunction(name, fn)
	}

	return fm
}

func (fm *FunctionMap) SetFunction(name string, function govaluate.ExpressionFunction) {
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
