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

package fastac

import (
	"github.com/abichinger/fastac/model"
	"github.com/abichinger/fastac/storage"
)

type IEnforcer interface {
	SetOption(option Option) error
	GetStorageController() *storage.StorageController

	GetModel() model.IModel
	SetModel(m model.IModel)

	GetAdapter() storage.Adapter
	SetAdapter(storage.Adapter)

	AddRule(rule []string) (bool, error)
	AddRules(rules [][]string) error
	RemoveRule(rule []string) (bool, error)
	RemoveRules(rules [][]string) error

	LoadPolicy() error
	SavePolicy() error

	Enforce(params ...interface{}) (bool, error)
	EnforceWithContext(ctx *Context, rvals ...interface{}) (bool, error)

	Filter(params ...interface{}) ([][]string, error)
	FilterWithContext(ctx *Context, rvals ...interface{}) ([][]string, error)

	RangeMatches(params []interface{}, fn func(rule []string) bool) error
	RangeMatchesWithContext(ctx *Context, rvals []interface{}, fn func(rule []string) bool) error

	Flush() error
}
