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

package policy

import (
	"testing"

	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/util"
	"github.com/stretchr/testify/assert"
)

func loadTestPolicy(t *testing.T, p *Policy, rules [][]string) {
	t.Helper()

	for _, rule := range rules {
		_, _ = p.AddRule(rule)
	}
}

func TestGetDistinct(t *testing.T) {
	def := defs.NewPolicyDef("p", "sub, obj, act")
	p := NewPolicy(def)
	rules := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	}

	loadTestPolicy(t, p, rules)

	subjects, _ := p.GetDistinct([]string{"sub"})
	objects, _ := p.GetDistinct([]string{"obj"})
	actions, _ := p.GetDistinct([]string{"act"})
	assert.ElementsMatch(t, util.Join2D(subjects, ""), []string{"alice", "bob", "data2_admin"})
	assert.ElementsMatch(t, util.Join2D(objects, ""), []string{"data1", "data2"})
	assert.ElementsMatch(t, util.Join2D(actions, ""), []string{"read", "write"})
}
