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

	"github.com/abichinger/fastac/model/eft"
	"github.com/abichinger/fastac/model/types"
)

const DefaultSep = ","
const DefaultRoleParty = "_"

var ArgReg = regexp.MustCompile(`([prg][0-9]*)(\.|_)([A-Za-z0-9_]+)`)
var pArgReg = regexp.MustCompile(`([pg][0-9]*)_([A-Za-z0-9_]+)`)
var rArgReg = regexp.MustCompile(`(r[0-9]*)_([A-Za-z0-9_]+)`)

type IDef interface {
	String() string
	GetKey() string
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

func (def *PolicyDef) GetEft(values []string) types.Effect {
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

func (def *PolicyDef) GetParameter(rule []string, name string) (string, error) {
	index, ok := def.argIndex[name]
	if !ok {
		return "", errors.New("parameter '" + name + "' not found.")
	}
	//check if rule is passed with key
	if len(rule) > len(def.args) {
		index++
	}
	if index >= len(rule) {
		return "", errors.New("rule has not enough values")
	}
	return rule[index], nil

}

func (def *PolicyDef) GetParameters(rule, names []string) ([]string, error) {
	params := make([]string, 0)
	for _, name := range names {
		value, err := def.GetParameter(rule, name)
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
		return "", errors.New("parameter '" + name + "' not found.")
	}
	//check if rule is passed with key
	if len(values) > len(def.args) {
		index++
	}
	if index >= len(values) {
		return "", errors.New("not enough values")
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
