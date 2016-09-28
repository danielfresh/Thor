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

package direct

import (
	"errors"
	"encoding/json"
	"fmt"
	"strconv"

	"thor/util"
	"thor/log"
	"thor/manager"
	"thor/manager/collector"
)

var (
	DEAL_TYPE = "collector"
	DEAL_NAME = "direct"
	metrics = make(map[string]InitFunc)

)

func init() {
	manager.RegisterDeal(DEAL_TYPE, DEAL_NAME, Init)
}

type InitFunc func() collector.Metric


func RegisterMetric(name string, metricInit InitFunc) error {

	if _, ok := metrics[name]; !ok {
		metrics[name] = metricInit
		log.Info("Regist metric: %s %+v", name, metricInit)

	} else {
		log.Warn("Already exists: %s %+v", name, metricInit)
		return nil
	}

	return nil
}

func GetMetric(name string) (collector.Metric, error) {

	if metricInit, ok := metrics[name]; ok {
		return metricInit(), nil
	}

	return nil, fmt.Errorf("when init, found not supported metric object: %s", name)
}

// Params:
// 1. uuid / containerid
// 2. metrics
func Init(options map[string]string) (manager.Deal, error) {

	if options == nil {
		return nil, errors.New("When init direct collector, get options: nil")
	}

	dc := &DirectCollector{
		Options: make(map[string]string),
	}

	// get uuid or containerid
	uuid, uuid_exist := options["uuid"]
	if uuid_exist {
		dc.Options["uuid"] = uuid
	}

	cid, cid_exist := options["containerid"];
	if  cid_exist {
		dc.Options["containerid"] = cid
	}

	if !uuid_exist && !cid_exist {
		return nil, errors.New("When init direct collector, get no uuid or containerid")
	}

	//get os version
	os_version, err := util.GetOsVersion()
	if err != nil {
		log.Error("Error while GetOsVersion: %s", err.Error())
		return nil, errors.New("Error while GetOsVersion, get no os_version")
	}
	dc.Options["os_version"] = os_version

	// get metrics
	if metricstr, ok := options["metrics"]; ok {
		var metrics []string

		err := json.Unmarshal([]byte(metricstr), &metrics)
		if err != nil {
			return nil, fmt.Errorf("Error when unmarshal %s", metricstr)
		}

		for _, metric := range metrics {
			if metricHandle, err := GetMetric(metric); err == nil {
				dc.Metrics = append(dc.Metrics, metricHandle)
			} else {
				log.Error("%s", err.Error())
				continue
			}
		}

	} else {
		return nil, errors.New("When init direct collector, get metrices: nil")
	}


	return dc, nil
}

type DirectCollector struct {
	Metrics []collector.Metric

	// uuid -> PID && containerID
	Options map[string]string
}

//Interface DEAL

func (dc *DirectCollector)Run() (map[string][]map[string]string, error) {

	err := dc.CheckOptions()
	if err != nil {
		return map[string][]map[string]string{}, err
	}

	meters, err := dc.Collect(dc.Options)
	if err != nil {
		return meters, err
	}

	return meters, nil
}

func (dc *DirectCollector)CheckOptions() error {

	cid, cid_exist := dc.Options["containerid"]

	// Get containerid and pid by name
	if !cid_exist || cid == "" {
		uuid, uuid_exist := dc.Options["uuid"]
		if !uuid_exist {
			return errors.New("Find neither containerid nor uuid.")
		}

		coninfo, err := util.GetContainerIdByUUID(uuid)
		if err != nil {
			return err
		}

		dc.Options["pid"] = strconv.Itoa(coninfo.State.Pid)
		dc.Options["containerid"] = coninfo.Id
	} else {
		coninfo, err := util.GetPIDByContainerId(cid)
		if err != nil {
			return err
		}

		dc.Options["pid"] = strconv.Itoa(coninfo.State.Pid)
	}

	_, cpu_set_exist := dc.Options["cpu_set"]
	containerid, containerid_exist := dc.Options["containerid"]
	os_version, _ := dc.Options["os_version"]
	if !cpu_set_exist && containerid_exist {
		// get cpu_set
		cpu_set, err := util.GetCpuSet(containerid, os_version)
		if err == nil {
			dc.Options["cpu_set"] = cpu_set
		}
	}

	return nil
}

func (dc *DirectCollector)GetDealType() string {
	return DEAL_TYPE
}

// Interface Collector (unused)

// Collect metrics from this collector.
func (dc *DirectCollector)Collect(option map[string]string) (map[string][]map[string]string, error) {

	meters := make(map[string][]map[string]string)
	for _, metric := range dc.Metrics {
		meter, err := metric.Collect(option)
		if err != nil {
			continue
		}

		meters[metric.GetName()] = meter
	}

	return meters, nil
}

// Return all metrics associated with this collector
func (dc *DirectCollector)GetMetrics() []collector.Metric {
	return dc.Metrics
}

// Name of this collector.
func (dc *DirectCollector)GetName() string {
	return DEAL_NAME
}
