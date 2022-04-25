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

package storage

import (
	"github.com/abichinger/fastac/api"
)

// Adapter is the interface for Casbin adapters.
type Adapter interface {
	// LoadPolicy loads all policy rules from the storage.
	LoadPolicy(model api.IAddRuleBool) error
	// SavePolicy saves all policy rules to the storage.
	SavePolicy(model api.IRangeRules) error
}

type SimpleAdapter interface {
	Adapter

	api.IAddRule
	api.IRemoveRule
}

// type FilteredAdapter interface {
// 	Adapter

// 	// LoadFilteredPolicy loads only policy rules that match the filter.
// 	LoadFilteredPolicy(model *model.Model, filter interface{}) error
// 	// IsFiltered returns true if the loaded policy has been filtered.
// 	IsFiltered() bool
// }

// BatchAdapter is the interface for Casbin adapters with multiple add and remove policy functions.
type BatchAdapter interface {
	Adapter

	api.IAddRules
	api.IRemoveRules
}
