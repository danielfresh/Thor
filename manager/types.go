/*
Copyright 2016 The Thor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package manager


// Type of metric being exported.
type MetricType string

type Deal interface {

	////init
	//Init(config map[string]string) error

	// execute
	Run() (map[string][]map[string]string, error)

	// type
	GetDealType() string
}