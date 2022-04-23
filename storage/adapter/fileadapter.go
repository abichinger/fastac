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

package adapter

import (
	"bufio"
	"os"
	"strings"

	"github.com/abichinger/fastac/api"
	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/model/types"
	"github.com/abichinger/fastac/util"
)

type FileAdapter struct {
	path string
}

type RuleSet struct {
	*policy.Policy
}

func NewRuleSet() *RuleSet {
	def := defs.NewPolicyDef("", "")
	return &RuleSet{Policy: policy.NewPolicy(def)}
}

func (set *RuleSet) AddRule(rule []string) (bool, error) {
	return set.AddPolicy(rule), nil
}

func (set *RuleSet) RemoveRule(rule []string) (bool, error) {
	return set.RemovePolicy(rule), nil
}

func (set *RuleSet) RangeRules(fn func(rule []string) bool) {
	set.Range(func(hash string, rule types.Rule) bool {
		return fn(rule)
	})
}

func NewFileAdapter(path string) *FileAdapter {
	return &FileAdapter{path: path}
}

func (a *FileAdapter) LoadPolicy(model api.IAddRuleBool) error {
	file, err := os.Open(a.path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := LoadPolicyLine(scanner.Text(), model); err != nil {
			return err
		}
	}

	return scanner.Err()
}

func getWriter(path string) (*bufio.Writer, error) {
	if exists, err := util.FileExists(path); err != nil {
		return nil, err
	} else if exists {
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	if _, err := os.Create(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return bufio.NewWriter(f), nil
}

func (a *FileAdapter) SavePolicy(model api.IRangeRules) error {
	writer, err := getWriter(a.path)
	if err != nil {
		return err
	}
	model.RangeRules(func(rule []string) bool {
		if _, err = writer.WriteString(strings.Join(rule, ", ") + "\n"); err != nil {
			return false
		}
		return true
	})
	if err != nil {
		return err
	}

	return writer.Flush()
}

func (a *FileAdapter) AddRule(rule []string) error {
	rs := NewRuleSet()
	if err := a.LoadPolicy(rs); err != nil {
		return err
	}
	rs.AddPolicy(rule)
	if err := a.SavePolicy(rs); err != nil {
		return err
	}
	return nil
}

func (a *FileAdapter) RemoveRule(rule []string) error {
	rs := NewRuleSet()
	if err := a.LoadPolicy(rs); err != nil {
		return err
	}
	if _, err := rs.RemoveRule(rule); err != nil {
		return err
	}
	if err := a.SavePolicy(rs); err != nil {
		return err
	}
	return nil
}

func (a *FileAdapter) AddRules(rules [][]string) error {
	rs := NewRuleSet()
	if err := a.LoadPolicy(rs); err != nil {
		return err
	}
	for _, rule := range rules {
		if _, err := rs.AddRule(rule); err != nil {
			return err
		}
	}
	if err := a.SavePolicy(rs); err != nil {
		return err
	}
	return nil
}

func (a *FileAdapter) RemoveRules(rules [][]string) error {
	rs := NewRuleSet()
	if err := a.LoadPolicy(rs); err != nil {
		return err
	}
	for _, rule := range rules {
		if _, err := rs.RemoveRule(rule); err != nil {
			return err
		}
	}
	if err := a.SavePolicy(rs); err != nil {
		return err
	}
	return nil
}
