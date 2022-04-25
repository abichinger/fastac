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
	"github.com/abichinger/fastac/model/kind"
	"github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/util"
	"github.com/stretchr/testify/assert"
)

func testRangeMatches(t *testing.T, matcher *Matcher, expected [][]string, rDef defs.RequestDef, rvals []interface{}, fm fm.FunctionMap) {
	t.Helper()
	rules := [][]string{}
	err := matcher.RangeMatches(rDef, rvals, fm, func(rule kind.Rule) bool {
		rules = append(rules, rule)
		return true
	})
	if err != nil {
		t.Error(err.Error())
	}

	assert.ElementsMatch(t, util.Join2D(expected, ","), util.Join2D(rules, ","))
}

func TestRangeMatches(t *testing.T) {

	fm := fm.DefaultFunctionMap()

	pDef := defs.NewPolicyDef("p", "sub, obj, act")
	p := policy.NewPolicy(pDef)

	rDef := defs.NewRequestDef("r", "sub, obj, act")

	mDef := defs.NewMatcherDef("m")
	mDef.AddStage(0, "r.sub == p.sub")
	mDef.AddStage(1, "r.obj == p.obj && r.act == p.act")

	m1 := NewMatcher(pDef, p, mDef.Stages())
	m2 := NewMatcher(pDef, p, mDef.Stages()[:1])

	rules := [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "read"},
		{"alice", "data1", "write"},
		{"alice", "data1", "delete"},
		{"bob", "data1", "read"},
		{"bob", "data2", "read"},
	}

	for _, rule := range rules {
		_, _ = p.AddRule(rule)
	}

	expected1 := [][]string{
		{"alice", "data2", "read"},
	}

	expected2 := [][]string{
		{"bob", "data1", "read"},
		{"bob", "data2", "read"},
	}

	testRangeMatches(t, m1, expected1, *rDef, []interface{}{"alice", "data2", "read"}, *fm)
	testRangeMatches(t, m2, expected2, *rDef, []interface{}{"bob", "", ""}, *fm)
}
