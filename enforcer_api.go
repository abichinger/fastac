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
	"github.com/abichinger/fastac/storage/adapter"
)

type IEnforcer interface {
	GetModel() model.IModel
	SetModel(m model.IModel)
	GetAdapter() *adapter.Adapter
	SetAdapter(*adapter.Adapter)

	Enforce(rvals ...interface{}) (bool, error)
	EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error)
	EnforceWithKeys(mKey string, rKey string, eKey string, rvals ...interface{})

	Filter(rvals ...interface{}) (bool, error)
	FilterWithMatcher(matcher string, rvals ...interface{}) (bool, error)
	FilterWithKeys(mKey string, rKey string, rvals ...interface{}) (bool, error)

	AddRule(params ...string) (bool, error)
	RemoveRule(params ...string) (bool, error)
}
