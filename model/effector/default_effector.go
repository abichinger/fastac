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
	"errors"

	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/eft"
	"github.com/abichinger/fastac/model/types"
)

// DefaultEffector is default effector for Casbin.
type DefaultEffector struct {
	*defs.EffectDef
}

// NewDefaultEffector is the constructor for DefaultEffector.
func NewEffector(def *defs.EffectDef) *DefaultEffector {
	e := DefaultEffector{}
	e.EffectDef = def
	return &e
}

func (e *DefaultEffector) MergeEffects(effects []types.Effect, matches []types.Rule, complete bool) (types.Effect, types.Rule, error) {

	if complete {
		switch e.Expr() {
		case "some(where(p.eft==allow))":
			return eft.Deny, types.Rule{}, nil
		case "!some(where(p.eft==deny))":
			return eft.Allow, types.Rule{}, nil
		case "some(where(p.eft==allow))&&!some(where(p.eft==deny))":
			if len(matches) == 0 {
				return eft.Deny, types.Rule{}, nil
			}
			return effects[0], matches[0], nil
		}
		return eft.Deny, types.Rule{}, errors.New("unsupported effect")
	}

	effect := eft.Indeterminate
	match := types.Rule{}

	if len(effects) > 0 {
		effect = effects[len(effects)-1]
	}
	if len(matches) > 0 {
		match = matches[len(matches)-1]
	}

	switch e.Expr() {
	case "some(where(p.eft==allow))":
		if effect == eft.Allow {
			return effect, match, nil
		}
	case "!some(where(p.eft==deny))":
		if effect == eft.Deny {
			return effect, match, nil
		}
	case "some(where(p.eft==allow))&&!some(where(p.eft==deny))":
		if effect == eft.Deny {
			return effect, match, nil
		}
	default:
		return eft.Deny, types.Rule{}, errors.New("unsupported effect")
	}

	return eft.Indeterminate, match, nil
}
