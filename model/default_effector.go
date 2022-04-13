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

package model

import (
	"errors"
)

// DefaultEffector is default effector for Casbin.
type DefaultEffector struct {
	*EffectDef
}

// NewDefaultEffector is the constructor for DefaultEffector.
func NewDefaultEffector(key, expr string) *DefaultEffector {
	e := DefaultEffector{}
	e.EffectDef = NewEffectDef(key, expr)
	return &e
}

func (e *DefaultEffector) MergeEffects(effects []Effect, matches []Rule, complete bool) (Effect, Rule, error) {

	if complete {
		switch e.Expr() {
		case "some(where(p.eft==allow))":
			return Deny, Rule{}, nil
		case "!some(where(p.eft==deny))":
			return Allow, Rule{}, nil
		case "some(where(p.eft==allow))&&!some(where(p.eft==deny))":
			if len(matches) == 0 {
				return Deny, Rule{}, nil
			}
			return effects[0], matches[0], nil
		}
		return Deny, Rule{}, errors.New("unsupported effect")
	}

	effect := Indeterminate
	match := Rule{}

	if len(effects) > 0 {
		effect = effects[len(effects)-1]
	}
	if len(matches) > 0 {
		match = matches[len(matches)-1]
	}

	switch e.Expr() {
	case "some(where(p.eft==allow))":
		if effect == Allow {
			return effect, match, nil
		}
		break
	case "!some(where(p.eft==deny))":
		if effect == Deny {
			return effect, match, nil
		}
		break
	case "some(where(p.eft==allow))&&!some(where(p.eft==deny))":
		if effect == Deny {
			return effect, match, nil
		}
		break
	default:
		return Deny, Rule{}, errors.New("unsupported effect")
	}

	return Indeterminate, match, nil
}
