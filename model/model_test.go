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
	"io/ioutil"
	"strings"
	"testing"

	"github.com/abichinger/fastac/util"
	"github.com/stretchr/testify/assert"
)

func TestToString(t *testing.T) {

	models := []string{"../examples/basic_model.conf", "../examples/rbac_model.conf", "../examples/rbac_model_index.conf", "../examples/multiple_policy_definitions_model.conf"}

	minify := func(s string) string {
		s = strings.ReplaceAll(s, " ", "")
		s = strings.ReplaceAll(s, "\n", "")
		return strings.ReplaceAll(s, "\r", "")
	}

	for _, model := range models {
		m, err := NewModelFromFile(model)
		if err != nil {
			t.Error(err.Error())
		}

		modelStr, readErr := ioutil.ReadFile(model)
		if readErr != nil {
			t.Error(readErr.Error())
		}

		lines := strings.Split(string(modelStr), "\n")
		filteredLines := []string{}
		for _, line := range lines {
			if len(line) == 0 || line[0] == '#' || line[0] == ';' {
				continue
			}
			filteredLines = append(filteredLines, line)
		}

		assert.Equal(t, minify(strings.Join(filteredLines, "")), minify(m.String()))
	}

}

func TestRangeRules(t *testing.T) {

	rules := [][]string{
		{"p", "g1", "data1", "read"},
		{"p", "g1", "data2", "read"},
		{"p", "g1", "data3", "read"},
		{"p", "g1", "data4", "read"},

		{"g", "u1", "g1"},
		{"g", "u1", "g2"},
		{"g", "u2", "g3"},
		{"g", "u2", "g4"},
	}

	m, err := NewModelFromFile("../examples/rbac_model.conf")
	if err != nil {
		t.Error(err.Error())
	}

	for _, rule := range rules {
		_, _ = m.AddRule(rule)
	}

	actualRules := [][]string{}
	m.RangeRules(func(rule []string) bool {
		actualRules = append(actualRules, rule)
		return true
	})

	assert.ElementsMatch(t, util.Join2D(rules, ","), util.Join2D(actualRules, ","))
}
