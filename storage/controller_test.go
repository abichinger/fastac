package storage

import (
	"testing"

	"example.com/fastac/api"
	"example.com/fastac/model"
	"example.com/fastac/storage/adapter"
	"github.com/stretchr/testify/assert"
	em "github.com/vansante/go-event-emitter"
)

type EmitterMock struct {
	handlers map[em.EventType]em.HandleFunc
}

func NewEmitterMock() *EmitterMock {
	return &EmitterMock{make(map[em.EventType]em.HandleFunc)}
}

func (e *EmitterMock) AddListener(event em.EventType, handler em.HandleFunc) (listener *em.Listener) {
	e.handlers[event] = handler
	return nil
}

func (e *EmitterMock) RemoveListener(event em.EventType, listener *em.Listener) {
	delete(e.handlers, event)
}

type AdapterMock interface {
	adapter.Adapter
	AddCalls() int
	RemoveCalls() int
}

type SimpleAdapterMock struct {
	addCalls    int
	removeCalls int
}

func (a *SimpleAdapterMock) AddCalls() int                           { return a.addCalls }
func (a *SimpleAdapterMock) RemoveCalls() int                        { return a.removeCalls }
func (a *SimpleAdapterMock) LoadPolicy(model api.IAddRuleBool) error { return nil }
func (a *SimpleAdapterMock) SavePolicy(model api.IRangeRules) error  { return nil }
func (a *SimpleAdapterMock) AddRule(rules []string) error {
	a.addCalls++
	return nil
}
func (a *SimpleAdapterMock) RemoveRule(rules []string) error {
	a.removeCalls++
	return nil
}

type BatchAdapterMock struct {
	SimpleAdapterMock
}

func (a *BatchAdapterMock) AddRules(rules [][]string) error {
	a.addCalls++
	return nil
}
func (a *BatchAdapterMock) RemoveRules(rules [][]string) error {
	a.removeCalls++
	return nil
}

func TestFlush(t *testing.T) {
	e := NewEmitterMock()

	adapters := []struct {
		adapter        AdapterMock
		addExpected    int
		removeExpected int
	}{
		{&SimpleAdapterMock{}, 3, 2},
		{&BatchAdapterMock{}, 2, 1},
	}

	for _, a := range adapters {
		sc := NewStorageController(e, a.adapter, false)

		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data2", "read"})
		e.handlers[model.RULE_REMOVED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_REMOVED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data1", "read"})

		assert.Equal(t, 0, a.adapter.AddCalls())
		assert.Equal(t, 0, a.adapter.RemoveCalls())
		sc.Flush()
		assert.Equal(t, a.addExpected, a.adapter.AddCalls())
		assert.Equal(t, a.removeExpected, a.adapter.RemoveCalls())
	}

}

func TestAutosave(t *testing.T) {
	e := NewEmitterMock()

	adapters := []struct {
		adapter        AdapterMock
		addExpected    int
		removeExpected int
	}{
		{&SimpleAdapterMock{}, 3, 2},
		{&BatchAdapterMock{}, 3, 2},
	}

	for _, a := range adapters {
		NewStorageController(e, a.adapter, true)

		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data2", "read"})
		e.handlers[model.RULE_REMOVED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_REMOVED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data1", "read"})

		assert.Equal(t, a.addExpected, a.adapter.AddCalls())
		assert.Equal(t, a.removeExpected, a.adapter.RemoveCalls())
	}

}

func TestAdd(t *testing.T) {
	e := NewEmitterMock()

	adapters := []struct {
		adapter        AdapterMock
		addExpected    int
		removeExpected int
	}{
		{&SimpleAdapterMock{}, 3, 2},
		{&BatchAdapterMock{}, 2, 1},
	}

	for _, a := range adapters {
		sc := NewStorageController(e, a.adapter, true)
		sc.AddWait(5)

		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data2", "read"})
		e.handlers[model.RULE_REMOVED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_REMOVED]([]string{"p", "alice", "data1", "read"})
		e.handlers[model.RULE_ADDED]([]string{"p", "alice", "data1", "read"})

		assert.Equal(t, a.addExpected, a.adapter.AddCalls())
		assert.Equal(t, a.removeExpected, a.adapter.RemoveCalls())
	}

}

func TestEnableDisable(t *testing.T) {
	e := em.NewEmitter(false)

	adapters := []struct {
		adapter        AdapterMock
		addExpected    int
		removeExpected int
	}{
		{&SimpleAdapterMock{}, 1, 1},
		{&BatchAdapterMock{}, 1, 1},
	}

	for _, a := range adapters {
		sc := NewStorageController(e, a.adapter, true)

		sc.Disable()
		e.EmitEvent(model.RULE_ADDED, []string{"p", "alice", "data1", "read"})
		e.EmitEvent(model.RULE_REMOVED, []string{"p", "alice", "data1", "read"})

		assert.Equal(t, 0, a.adapter.AddCalls())
		assert.Equal(t, 0, a.adapter.RemoveCalls())

		sc.Enable()
		e.EmitEvent(model.RULE_ADDED, []string{"p", "alice", "data1", "read"})
		e.EmitEvent(model.RULE_REMOVED, []string{"p", "alice", "data1", "read"})

		assert.Equal(t, a.addExpected, a.adapter.AddCalls())
		assert.Equal(t, a.removeExpected, a.adapter.RemoveCalls())
	}

}
