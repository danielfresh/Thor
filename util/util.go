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

package util

import (
	"net"
	"strings"
	"strconv"
	"io/ioutil"
	"net/http"
	"os"
	"encoding/json"
	"errors"

	"thor/log"
	"thor/config"
)

type ContainerInfoState struct {
	Pid int
}

type ContainerInfo struct {
	Id  string
	State ContainerInfoState
}

func GetLocalAddrs() (addrs []string, err error) {

	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	for _, ifaddr := range ifaddrs {
		ip := strings.Split(ifaddr.String(), "/")
		addrs = append(addrs, ip[0])
	}

	return
}

func Reverse(s string) string {
	runes := []rune(s)
	for from, to := 0, len(runes)-1; from < to; from, to = from+1, to-1 {
		runes[from], runes[to] = runes[to], runes[from]
	}
	return string(runes)
}

func ParseCpuSet(cpu_set string) []int {
	cpus := strings.Split(cpu_set, ",")
	var cpu_sets []int
	for _, cpu_num := range cpus {
		if strings.Contains(cpu_num, "-") {
			cpu_nums := strings.Split(cpu_num, "-")
			start, _ := strconv.Atoi(cpu_nums[0])
			end, _ := strconv.Atoi(cpu_nums[1])
			for i := start; i <= end; i++ {
				cpu_sets = append(cpu_sets, i)
			}
		} else {
			num, _ := strconv.Atoi(cpu_num)
			cpu_sets = append(cpu_sets, num)
		}
	}
	return cpu_sets
}

func GetContainerIdByUUID(uuid string) (ContainerInfo, error) {

	var coninfo ContainerInfo
	var err error = errors.New("Get container_id or pid failed!")
	containname := "nova-"+uuid
	transport := http.Transport{
		DisableKeepAlives: true,
	}
	client := http.Client{
		Transport: &transport,
	}
	request, _ := http.NewRequest("GET", "http://127.0.0.1:5050/containers/"+containname+"/json", nil)
	request.Header.Set("Content-type","application/json")

	for i :=1; i<=2; i++ {
		response, err := client.Do(request)
		defer response.Body.Close()
		if err != nil {
			return coninfo, err
		}
		if response.StatusCode == 200 {
			body, _ := ioutil.ReadAll(response.Body)
			err = json.Unmarshal(body, &coninfo)
			if err != nil {
				log.Error("Error while json.Unmarshal body:%s", err.Error())
				//return coninfo, err
			} else {
				if coninfo.State.Pid == 0 {
					continue
				}
				return coninfo, nil
			}
		}
	}

	return coninfo, err
}

func GetPIDByContainerId(cid string) (ContainerInfo, error) {

	var coninfo ContainerInfo
	var err error = errors.New("Get container pid failed!")

	transport := http.Transport{
		DisableKeepAlives: true,
	}
	client := http.Client{
		Transport: &transport,
	}
	request, _ := http.NewRequest("GET", "http://127.0.0.1:5050/containers/" + cid + "/json", nil)
	request.Header.Set("Content-type","application/json")

	for i :=1; i<=2; i++ {
		response, err := client.Do(request)
		defer response.Body.Close()
		if err != nil {
			return coninfo, err
		}
		if response.StatusCode == 200 {
			body, _ := ioutil.ReadAll(response.Body)
			err = json.Unmarshal(body, &coninfo)
			if err != nil {
				log.Error("Error while json.Unmarshal body:%s", err.Error())
				//return coninfo, err
			} else {
				if coninfo.State.Pid == 0 {
					continue
				}
				return coninfo, nil
			}
		}
	}

	return coninfo, err
}

func GetCpuSet(contain_id string, os_version string) (string, error) {
	// 1-3,7-9,14
	cpuset_path, err := JoinPath(os_version, "cpuset", contain_id, "cpuset.cpus")
	if err != nil{
		log.Error("Error while Join cpuset path:%s", err.Error())
		return "", err
	}
	fi, err := os.Open(cpuset_path)
	defer fi.Close()
	if err != nil{
		log.Error("Error while open cpuset_path:%s", err.Error())
		return "", err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil{
		log.Error("Error while read file cpuset_path:%s", err.Error())
		return "", err
	}
	cpu_set := strings.TrimSpace(string(fd))
	if config.ThConf.General.OverSold {
		cpu_set = cpu_set[:len(cpu_set)-len(config.ThConf.General.OverSoldCpus)]
	}
	return cpu_set, nil
}

func GetOsVersion() (string, error) {
	path := "/proc/version"
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open %s:%s", path, err.Error())
		return "", err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read %s:%s", path, err.Error())
		return "", err
	}

	os_version := strings.Fields(string(fd))[2]
	return os_version, nil
}

func JoinPath(os_version string, meter string, contain_id string, meter_file string) (string, error){
	if strings.HasPrefix(os_version, "2.") {
		path := "/cgroup/"+meter+"/docker/"+contain_id+"/"+meter_file
		return path, nil
	}
	if strings.HasPrefix(os_version, "3.") {
		path := "/sys/fs/cgroup/"+meter+"/system.slice/docker-"+contain_id+".scope/"+meter_file
		return path, nil
	}
	return "", errors.New("Join path failed!")
}