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
	"github.com/Knetic/govaluate"
	"github.com/abichinger/fastac/util"
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
