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

func (e *DefaultEffector) MergeEffects(effects []types.Effect, matches [][]string, complete bool) (types.Effect, []string, error) {

	if complete {
		switch e.Expr() {
		case eft.SOME_ALLOW:
			return eft.Deny, []string{}, nil
		case eft.NO_DENY:
			return eft.Allow, []string{}, nil
		case eft.SOME_ALLOW_NO_DENY:
			if len(matches) == 0 {
				return eft.Deny, []string{}, nil
			}
			return effects[0], matches[0], nil
		}
		return eft.Deny, []string{}, errors.New("unsupported effect")
	}

	effect := eft.Indeterminate
	match := []string{}

	if len(effects) > 0 {
		effect = effects[len(effects)-1]
	}
	if len(matches) > 0 {
		match = matches[len(matches)-1]
	}

	switch e.Expr() {
	case eft.SOME_ALLOW:
		if effect == eft.Allow {
			return effect, match, nil
		}
	case eft.NO_DENY:
		if effect == eft.Deny {
			return effect, match, nil
		}
	case eft.SOME_ALLOW_NO_DENY:
		if effect == eft.Deny {
			return effect, match, nil
		}
	default:
		return eft.Deny, []string{}, errors.New("unsupported effect")
	}

	return eft.Indeterminate, match, nil
}
