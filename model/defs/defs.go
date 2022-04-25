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

package defs

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/abichinger/fastac/model/eft"
	"github.com/abichinger/fastac/model/kind"
)

const DefaultSep = ","
const DefaultRoleParty = "_"

var ArgReg = regexp.MustCompile(`([pr][0-9]*)(\.|_)([A-Za-z0-9_]+)`)
var pArgReg = regexp.MustCompile(`(p[0-9]*)_([A-Za-z0-9_]+)`)
var rArgReg = regexp.MustCompile(`(r[0-9]*)_([A-Za-z0-9_]+)`)

type IDef interface {
	String() string
}

type PolicyDef struct {
	key      string
	args     []string
	argIndex map[string]int
}

func NewPolicyDef(key, arguments string) *PolicyDef {
	def := &PolicyDef{}
	def.key = key
	def.args = strings.Split(strings.ReplaceAll(arguments, " ", ""), DefaultSep)
	def.argIndex = make(map[string]int, len(def.args))
	for i, arg := range def.args {
		def.argIndex[key+"_"+arg] = i
	}
	return def
}

func (def *PolicyDef) GetKey() string {
	return def.key
}

func (def *PolicyDef) GetArgs() []string {
	return def.args
}

func (def *PolicyDef) Has(name string) bool {
	_, ok := def.argIndex[name]
	return ok
}

func (def *PolicyDef) GetEft(values []string) kind.Effect {
	eftArg := def.key + "_eft"
	if def.Has(eftArg) {
		eftStr, _ := def.GetParameter(values, eftArg)
		switch eftStr {
		case "", "allow":
			return eft.Allow
		case "deny":
			return eft.Deny
		default:
			return eft.Indeterminate
		}
	}
	return eft.Allow
}

func (def *PolicyDef) GetParameter(values []string, name string) (string, error) {
	index, ok := def.argIndex[name]
	if !ok {
		return "", errors.New("No parameter '" + name + "' found.")
	}
	return values[index], nil
}

func (def *PolicyDef) GetParameters(values, names []string) (kind.Rule, error) {
	params := make([]string, 0)
	for _, name := range names {
		value, err := def.GetParameter(values, name)
		if err != nil {
			return nil, err
		}
		params = append(params, value)
	}
	return params, nil
}

func (def *PolicyDef) String() string {
	return fmt.Sprintf("%s = %s", def.key, strings.Join(def.args, DefaultSep+" "))
}

type RequestDef struct {
	key      string
	args     []string
	argIndex map[string]int
}

func (def *RequestDef) GetKey() string {
	return def.key
}

func NewRequestDef(key, arguments string) *RequestDef {
	def := &RequestDef{}
	def.key = key
	def.args = strings.Split(strings.ReplaceAll(arguments, " ", ""), DefaultSep)
	def.argIndex = make(map[string]int, len(def.args))
	for i, arg := range def.args {
		def.argIndex[key+"_"+arg] = i
	}
	return def
}

func (def *RequestDef) Has(name string) bool {
	_, ok := def.argIndex[name]
	return ok
}

func (def *RequestDef) GetParameter(values []interface{}, name string) (interface{}, error) {
	index, ok := def.argIndex[name]
	if !ok {
		return "", errors.New("No parameter '" + name + "' found.")
	}
	return values[index], nil
}

func (def *RequestDef) GetParameters(values []interface{}, names []string) ([]interface{}, error) {
	params := make([]interface{}, 0)
	for _, name := range names {
		value, err := def.GetParameter(values, name)
		if err != nil {
			return nil, err
		}
		params = append(params, value)
	}
	return params, nil
}

func (def *RequestDef) String() string {
	return fmt.Sprintf("%s = %s", def.key, strings.Join(def.args, DefaultSep+" "))
}

type MatcherDef struct {
	key    string
	stages []*MatcherStage
}

func NewMatcherDef(key string) *MatcherDef {
	return &MatcherDef{key, []*MatcherStage{}}
}

func (def *MatcherDef) GetKey() string {
	return def.key
}

func (def *MatcherDef) AddStage(index int, expr string) {
	newStage := NewMatcherStage(index, expr)
	for i, stage := range def.stages {
		if stage.index > newStage.index {
			def.stages = append(def.stages[0:i+1], def.stages[i:]...)
			def.stages[i] = newStage
			goto END
		}
	}
	def.stages = append(def.stages, newStage)
END:
}

func (def *MatcherDef) Stages() []*MatcherStage {
	return def.stages
}

func (def *MatcherDef) GetPolicyArgs() []string {
	args := []string{}
	for _, stage := range def.stages {
		args = append(args, stage.pArgs...)
	}
	return args
}

func (def *MatcherDef) GetRequestArgs() []string {
	args := []string{}
	for _, stage := range def.stages {
		args = append(args, stage.rArgs...)
	}
	return args
}

func (def *MatcherDef) GetPolicyKey() string {
	pArgs := def.GetPolicyArgs()
	pKey := "p"
	if len(pArgs) > 0 {
		pKey = strings.Split(pArgs[0], "_")[0]
	}
	return pKey
}

func (def *MatcherDef) String() string {
	if len(def.stages) == 1 {
		return fmt.Sprintf("%s = %s", def.key, ArgReg.ReplaceAllString(def.stages[0].expr, "${1}.${3}"))
	}

	defs := []string{}
	for i, stage := range def.stages {
		defs = append(defs, fmt.Sprintf("%s.%d = %s", def.key, i, ArgReg.ReplaceAllString(stage.expr, "${1}.${3}")))
	}
	return strings.Join(defs, "\n")

}

type MatcherStage struct {
	index int
	expr  string
	pArgs []string
	rArgs []string
}

func NewMatcherStage(index int, expr string) *MatcherStage {
	stage := &MatcherStage{}
	stage.index = index
	stage.expr = ArgReg.ReplaceAllString(expr, "${1}_${3}")
	stage.pArgs = pArgReg.FindAllString(stage.expr, -1)
	stage.rArgs = rArgReg.FindAllString(stage.expr, -1)
	return stage
}

func (stage *MatcherStage) GetPolicyArgs() []string {
	return stage.pArgs
}

func (stage *MatcherStage) GetRequestArgs() []string {
	return stage.rArgs
}

func (def *MatcherStage) NewExpressionWithFunctions(functions map[string]govaluate.ExpressionFunction) (*govaluate.EvaluableExpression, error) {
	return govaluate.NewEvaluableExpressionWithFunctions(def.expr, functions)
}

type EffectDef struct {
	key  string
	expr string
}

func NewEffectDef(key, expr string) *EffectDef {
	def := &EffectDef{}
	def.key = key
	def.expr = strings.ReplaceAll(expr, " ", "")
	return def
}

func (def *EffectDef) GetKey() string {
	return def.key
}

func (def *EffectDef) Expr() string {
	return def.expr
}

func (def *EffectDef) String() string {
	return fmt.Sprintf("%s = %s", def.key, def.expr)
}

type RoleDef struct {
	key   string
	nargs int
}

func NewRoleDef(key, arguments string) *RoleDef {
	def := &RoleDef{}
	def.key = key
	def.nargs = len(strings.Split(arguments, DefaultSep))
	return def
}

func (def *RoleDef) GetKey() string {
	return def.key
}

func (def *RoleDef) NArgs() int {
	return def.nargs
}

func (def *RoleDef) String() string {
	args := make([]string, def.nargs)
	for i := 0; i < def.nargs; i++ {
		args[i] = DefaultRoleParty
	}
	return fmt.Sprintf("%s = %s", def.key, strings.Join(args, DefaultSep))
}
