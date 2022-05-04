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

package model

import (
	"github.com/abichinger/fastac/api"
	"github.com/abichinger/fastac/model/defs"
	e "github.com/abichinger/fastac/model/effector"
	"github.com/abichinger/fastac/model/matcher"
	m "github.com/abichinger/fastac/model/matcher"
	p "github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/rbac"
	"github.com/abichinger/govaluate"
)

type IModel interface {
	api.IAddRuleBool
	api.IRemoveRuleBool
	api.IRangeRules
	api.IAddRemoveListener

	GetDef(sec byte, key string) (defs.IDef, bool)
	SetDef(sec byte, key string, value string) error
	RemoveDef(sec byte, key string) error

	GetRoleManager(key string) (rbac.IRoleManager, bool)
	SetRoleManager(key string, rm rbac.IRoleManager)

	GetPolicy(key string) (p.IPolicy, bool)
	SetPolicy(key string, policy p.IPolicy)

	GetEffector(key string) (e.IEffector, bool)
	SetEffector(key string, eft e.IEffector)

	GetMatcher(key string) (m.IMatcher, bool)
	SetMatcher(key string, matcher m.IMatcher)

	GetRequestDef(key string) (*defs.RequestDef, bool)
	SetRequestDef(key string, def *defs.RequestDef)

	ClearPolicy(key string) error

	SetFunction(name string, function govaluate.ExpressionFunction)
	RemoveFunction(name string) bool

	BuildMatcherFromDef(mDef *defs.MatcherDef) (matcher.IMatcher, error)

	RangeMatches(matcher matcher.IMatcher, rDef *defs.RequestDef, rvals []interface{}, fn func(rule []string) bool) error

	String() string
}
