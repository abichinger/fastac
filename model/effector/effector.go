// Copyright 2018 The casbin Authors. All Rights Reserved.
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

import "github.com/abichinger/fastac/model/kind"

// IEffector is the interface for FastAC effectors.
type IEffector interface {
	// MergeEffects merges a list of effects into a single one
	// This function gets called during the accumulation of effects and once more when all effects have been gathered
	// Returns the effect and the rule, which is responsible for the result
	MergeEffects(effects []kind.Effect, matches []kind.Rule, complete bool) (kind.Effect, kind.Rule, error)
}
