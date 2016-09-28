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

package adaptor

import (
	"errors"
	"encoding/json"
	"fmt"
)

func ParseRequest(data []byte, len int) (*Request, error) {

	if data == nil || len == 0 {
		return nil, errors.New("request is nil")
	}

	req := &Request{}

	err := json.Unmarshal(data[:len], req)
	if err != nil {
		return nil, fmt.Errorf("Json: Error when unmarshal request: %s", string(data[:len]))
	}

	// Check
	if req.Executions < 0 {
		req.Executions = 1
		//LOG
	}

	return req, nil
}

func PackResponse(data map[string][]map[string]string) (string, error) {

	if data == nil {
		return "", errors.New("Data to be marshalled is nil")
	}

	data_byte, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(data_byte), nil
}

