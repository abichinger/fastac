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

package api

import em "github.com/vansante/go-event-emitter"

type IAddRule interface {
	AddRule(rule []string) error
}

type IAddRuleBool interface {
	AddRule(rule []string) (bool, error)
}

type IAddRules interface {
	AddRules(rules [][]string) error
}

type IRemoveRule interface {
	RemoveRule(rule []string) error
}

type IRemoveRuleBool interface {
	RemoveRule(rule []string) (bool, error)
}

type IRemoveRules interface {
	RemoveRules(rules [][]string) error
}

type IAddListener interface {
	AddListener(event em.EventType, handler em.HandleFunc) (listener *em.Listener)
}

type IRemoveListener interface {
	RemoveListener(event em.EventType, listener *em.Listener)
}

type IAddRemoveListener interface {
	IAddListener
	IRemoveListener
}

type IRangeRules interface {
	RangeRules(fn func(rule []string) bool)
}
