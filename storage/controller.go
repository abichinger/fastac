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
	"errors"

	"github.com/abichinger/fastac/api"
	"github.com/abichinger/fastac/model"
	"github.com/abichinger/fastac/storage/adapter"
	eventemitter "github.com/abichinger/go-event-emitter"
)

type opcode int

const (
	add opcode = iota
	remove
)

type operation struct {
	opc  opcode
	rule []string
}

type listener struct {
	event    eventemitter.EventType
	listener *eventemitter.Listener
}

type StorageController struct {
	autosave  bool
	em        api.IAddRemoveListener
	adapter   adapter.Adapter
	q         []operation
	wait      int
	listeners []listener
}

func NewStorageController(eventemitter api.IAddRemoveListener, adapter adapter.Adapter, autosave bool) *StorageController {
	sc := &StorageController{
		em:        eventemitter,
		adapter:   adapter,
		autosave:  autosave,
		listeners: []listener{},
	}

	sc.Enable()

	return sc
}

func (sc *StorageController) addListener(event eventemitter.EventType, opc opcode) {
	l := sc.em.AddListener(event, func(arguments []interface{}) {
		rule := arguments[0].([]string)
		sc.addOp(opc, rule)
	})

	sc.listeners = append(sc.listeners, listener{event, l})
}

func (sc *StorageController) Enabled() bool {
	return len(sc.listeners) > 0
}

func (sc *StorageController) Enable() {

	if sc.Enabled() {
		return
	}

	listenerParams := []struct {
		evt eventemitter.EventType
		opc opcode
	}{
		{model.RULE_ADDED, add},
		{model.RULE_REMOVED, remove},
	}

	for _, params := range listenerParams {
		sc.addListener(params.evt, params.opc)
	}
}

func (sc *StorageController) Disable() {
	for _, listener := range sc.listeners {
		sc.em.RemoveListener(listener.event, listener.listener)
	}
	sc.listeners = []listener{}
}

func (sc *StorageController) addOp(opc opcode, rule []string) {
	sc.q = append(sc.q, operation{opc, rule})
	if sc.autosave {
		sc.wait--
		if sc.wait <= 0 {
			sc.Flush()
		}
	}
}

func (sc *StorageController) EnableAutosave() {
	sc.autosave = true
}

func (sc *StorageController) DisableAutosave() {
	sc.autosave = false
}

func (sc *StorageController) AutosaveEnabled() bool {
	return sc.autosave
}

func (sc *StorageController) flush() error {
	for len(sc.q) > 0 {
		operation := sc.q[0]
		sc.q = sc.q[1:]
		if err := sc.run(operation.opc, operation.rule); err != nil {
			return err
		}
	}
	return nil
}

func (sc *StorageController) batchFlush() error {

	rules := [][]string{}

	var currentOpc opcode
	if len(sc.q) > 0 {
		currentOpc = sc.q[0].opc
	}

	for len(sc.q) > 0 {

		operation := sc.q[0]
		sc.q = sc.q[1:]

		if currentOpc == operation.opc {
			rules = append(rules, operation.rule)
		} else {
			if err := sc.runBatch(currentOpc, rules); err != nil {
				return err
			}
			currentOpc = operation.opc
			rules = [][]string{operation.rule}
		}
	}

	if len(rules) > 0 {
		if err := sc.runBatch(currentOpc, rules); err != nil {
			return err
		}
	}
	return nil
}

func (sc *StorageController) Flush() error {
	var err error

	switch sc.adapter.(type) {
	case adapter.BatchAdapter:
		err = sc.batchFlush()
	case adapter.SimpleAdapter:
		err = sc.flush()
	default:
		err = errors.New("invalid adapter")
	}

	sc.wait = 0
	return err
}

func (sc *StorageController) run(opc opcode, rule []string) error {
	adapter := sc.adapter.(adapter.SimpleAdapter)
	var err error

	switch opc {
	case add:
		err = adapter.AddRule(rule)
	case remove:
		err = adapter.RemoveRule(rule)
	}
	return err
}

func (sc *StorageController) runBatch(opc opcode, rules [][]string) error {
	adapter := sc.adapter.(adapter.BatchAdapter)
	var err error

	switch opc {
	case add:
		err = adapter.AddRules(rules)
	case remove:
		err = adapter.RemoveRules(rules)
	}
	return err
}

func (sc *StorageController) AddWait(i int) {
	sc.wait += i
}
