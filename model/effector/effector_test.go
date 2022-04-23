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

package effector

import (
	"fmt"
	"strings"
	"testing"

	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/eft"
	"github.com/abichinger/fastac/model/types"
)

func genEffects(effects []types.Effect, n int) ([]types.Effect, []types.Rule) {
	e := make([]types.Effect, 0)
	m := make([]types.Rule, 0)

	for i := 0; i < n; i++ {
		e = append(e, effects[i%len(effects)])
		m = append(m, strings.Split(fmt.Sprintf("sub%d,obj%d,act%d", i, i, i), ","))
	}
	return e, m
}

func testMerge(t *testing.T, e Effector, effects []types.Effect, matches []types.Rule, complete bool, exprected types.Effect) {
	t.Helper()
	effect, _, err := e.MergeEffects(effects, matches, complete)
	if err != nil {
		t.Error(err.Error())
	}
	if effect != exprected {
		t.Errorf("%d supposed to be %d", effect, exprected)
	}
}

func TestSomeAllow(t *testing.T) {
	def := defs.NewEffectDef("e", "some(where (p.eft == allow))")
	e := NewEffector(def)

	effects, matches := genEffects([]types.Effect{eft.Allow}, 1)
	testMerge(t, e, effects, matches, false, eft.Allow)
	effects, matches = genEffects([]types.Effect{eft.Deny}, 1)
	testMerge(t, e, effects, matches, false, eft.Indeterminate)
	effects, matches = genEffects([]types.Effect{}, 0)
	testMerge(t, e, effects, matches, true, eft.Deny)
}

func TestNoDeny(t *testing.T) {
	def := defs.NewEffectDef("e", "!some(where (p.eft == deny))")
	e := NewEffector(def)

	effects, matches := genEffects([]types.Effect{eft.Allow}, 1)
	testMerge(t, e, effects, matches, false, eft.Indeterminate)
	effects, matches = genEffects([]types.Effect{eft.Deny}, 1)
	testMerge(t, e, effects, matches, false, eft.Deny)
	effects, matches = genEffects([]types.Effect{}, 0)
	testMerge(t, e, effects, matches, true, eft.Allow)
}

func TestSomeAllowNoDeny(t *testing.T) {
	def := defs.NewEffectDef("e", "some(where (p.eft == allow)) && !some(where (p.eft == deny))")
	e := NewEffector(def)

	effects, matches := genEffects([]types.Effect{eft.Allow}, 1)
	testMerge(t, e, effects, matches, false, eft.Indeterminate)
	effects, matches = genEffects([]types.Effect{eft.Deny}, 1)
	testMerge(t, e, effects, matches, false, eft.Deny)
	effects, matches = genEffects([]types.Effect{}, 0)
	testMerge(t, e, effects, matches, true, eft.Deny)
	effects, matches = genEffects([]types.Effect{eft.Allow}, 1)
	testMerge(t, e, effects, matches, true, eft.Allow)
}
