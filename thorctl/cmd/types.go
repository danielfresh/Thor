/*
Copyright 2016 The Thorctl Authors.

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

package cmd

type ContainerStatus struct {
	CpuUsage              []Metric `json:"CPU_Usage"`
	MEM_Usage             []Metric `json:"MEM_Usage"`
	Load                  []Metric `json:"Load"`
	Net_In_Bytes_Rate     []Metric `json:"Net_In_Bytes_Rate"`
	Net_Out_Bytes_Rate    []Metric `json:"Net_Out_Bytes_Rate"`
	Disk_Read_Bytes_Rate  []Metric `json:"Disk_Read_Bytes_Rate"`
	Disk_Write_Bytes_Rate []Metric `json:"Disk_Write_Bytes_Rate"`
	Succ                  []map[string]string `json:"Succ"`

	// error
	err                   error
}

type Metric struct {
	Volume    string `json:"volume"`
	Unit      string `json:"unit"`
	Timestamp string `json:"timestamp"`
}

type CmdResult map[string][]map[string]string
