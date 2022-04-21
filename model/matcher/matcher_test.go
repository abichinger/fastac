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

package matcher

import (
	"testing"

	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/fm"
	"github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/model/types"
)

func TestMatcher(t *testing.T) {

	fm := fm.DefaultFunctionMap()

	p := policy.NewPolicy("p", "sub, obj, act")

	rDef := defs.NewRequestDef("r", "sub, obj, act")

	mDef1 := defs.NewMatcherDef("m.1", "r.sub == p.sub")
	mDef2 := defs.NewMatcherDef("m.2", "r.obj == p.obj && r.act == p.act")
	m1 := NewMatcher(p, []*defs.MatcherDef{mDef1, mDef2})

	m2 := NewMatcher(p, []*defs.MatcherDef{mDef1})

	p.AddPolicy([]string{"alice", "data1", "read"})
	p.AddPolicy([]string{"alice", "data2", "read"})
	p.AddPolicy([]string{"alice", "data1", "write"})
	p.AddPolicy([]string{"alice", "data1", "delete"})
	p.AddPolicy([]string{"bob", "data1", "read"})
	p.AddPolicy([]string{"bob", "data2", "read"})

	t.Logf("M1")
	err := m1.RangeMatches(*rDef, []interface{}{"alice", "data2", "read"}, *fm, func(rule types.Rule) bool {
		t.Logf("match: %s", rule.Hash())
		return true
	})
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Logf("M2")
	err = m2.RangeMatches(*rDef, []interface{}{"alice", "", ""}, *fm, func(rule types.Rule) bool {
		t.Logf("match: %s", rule.Hash())
		return true
	})
	if err != nil {
		t.Errorf(err.Error())
	}
}
