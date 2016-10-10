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
	"io/ioutil"
	"os"
	"strings"
	"strconv"
	"time"
	"math"
	"os/exec"
	"bytes"
	"errors"

	"thor/log"
	"thor/util"
	"thor/config"
	"thor/manager/collector"
)

func init() {
	RegisterMetric("CPU_Usage", InitMetricCpuUsage)
	RegisterMetric("MEM_Usage", InitMetricMemUsage)
	RegisterMetric("Load", InitMetricLoad)
	RegisterMetric("Net_In_Bytes_Rate", InitMetricNetIn)
	RegisterMetric("Net_Out_Bytes_Rate", InitMetricNetOut)
	RegisterMetric("Disk_Read_Bytes_Rate", InitMetricDiskRead)
	RegisterMetric("Disk_Write_Bytes_Rate", InitMetricDiskWrite)
	RegisterMetric("Tcp_Connections", InitMetricTcpConns)
	RegisterMetric("Threads", InitMetricThreads)
	RegisterMetric("Processes", InitMetricProcesses)
}

func InitMetricCpuUsage() collector.Metric {
	return &CPU_Usage_Metric{
		Cache:make(map[string]float64),
	}
}

func InitMetricMemUsage() collector.Metric {
	return &MEM_Usage_Metric{}
}

func InitMetricLoad() collector.Metric {
	return &Load_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricNetIn() collector.Metric {
	return &NET_In_Bytes_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricNetOut() collector.Metric {
	return &NET_Out_Bytes_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricDiskRead() collector.Metric {
	return &Disk_Read_Bytes_Metric{
		Cache: make(map[string]float64),
		CacheDm: make(map[string]string),
	}
}

func InitMetricDiskWrite() collector.Metric {
	return &Disk_Write_Bytes_Metric{
		Cache: make(map[string]float64),
		CacheDm: make(map[string]string),
	}
}

func InitMetricTcpConns() collector.Metric {
	return &Tcp_Conns_Metric{}
}

func InitMetricThreads() collector.Metric {
	return &Threads_Metric{}
}

func InitMetricProcesses() collector.Metric {
	return &Processes_Metric{}
}

type CPU_Usage_Metric struct {
	Cache map[string]float64
}

type MEM_Usage_Metric struct {

}

type Load_Metric struct {
	Cache map[string]float64
}

type NET_In_Bytes_Metric struct {
	Cache map[string]float64
}

type NET_Out_Bytes_Metric struct {
	Cache map[string]float64
}

type Disk_Read_Bytes_Metric struct {
	Cache   map[string]float64
	CacheDm map[string]string
}

type Disk_Write_Bytes_Metric struct {
	Cache   map[string]float64
	CacheDm map[string]string
}

type Tcp_Conns_Metric struct {

}

type Threads_Metric struct {

}

type Processes_Metric struct {

}


// Get the name of the metric.
func (cm *CPU_Usage_Metric)GetName() string {
	return "CPU_Usage"
}

// Collect metric.
func (cm *CPU_Usage_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "%", "label": "cpu.usage"}}
	cpu_set := util.ParseCpuSet(option["cpu_set"])
	total, err := GetCpuTotal(cpu_set)
	if err != nil {
		log.Error("Error while get total from /proc/stat:%s", err.Error())
		return sample, err
	}
	cpu_use, err := GetCpuUse(option["containerid"], cpu_set, option["os_version"])
	if err != nil {
		log.Error("Error while get cpu_use_time:%s", err.Error())
		return sample, err
	}
	total_pre, total_exist := cm.Cache["cpu_total_use"]
	cpu_use_pre, cpu_use_exist := cm.Cache["cpu_per_use"]
	if total_exist && cpu_use_exist {
		cpu_util := 100.0 * (cpu_use - cpu_use_pre) / (total - total_pre)
		if cpu_util > 100 {
			cpu_util = 100
		}
		sample[0]["volume"] = strconv.FormatFloat(cpu_util, 'g', -1, 64)
	}
	cm.Cache["cpu_total_use"] = total
	cm.Cache["cpu_per_use"] = cpu_use

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get cpu_util volume failed!")
	}

	return sample, nil
}

func GetCpuTotal(cpu_set []int) (float64, error) {
	path := "/proc/stat"
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open /proc/stat:%s", err.Error())
		return 0, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file /proc/stat:%s", err.Error())
		return 0, err
	}

	cpu_data := strings.Split(string(fd), "\n")

	var total float64 = 0.0
	for _, cpu_no := range cpu_set {
		cpu := strings.Fields(cpu_data[cpu_no + 1])
		for _, time := range cpu[1:] {
			times, _ := strconv.ParseFloat(time, 64)
			total += times
		}
	}

	return total, nil
}

func GetCpuUse(contain_id string, cpu_set []int, os_version string) (float64, error) {
	path, err := util.JoinPath(os_version, "cpuacct", contain_id, "cpuacct.usage_percpu")
	if err != nil{
		log.Error("Error while Join cpuacct.usage_percpu path:%s", err.Error())
		return 0.0, err
	}
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open /proc/stat:%s", err.Error())
		return 0.0, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file /proc/stat:%s", err.Error())
		return 0.0, err
	}

	var cpu_time float64 = 0.0
	cpu_info := strings.Fields(string(fd))
	if strings.HasPrefix(os_version, "2.") {
		for _, cpu_no := range cpu_set {
			times, _ := strconv.ParseFloat(cpu_info[cpu_no], 64)
			cpu_time += times
		}
		return cpu_time / 10000000, nil
	} else if strings.HasPrefix(os_version, "3.") {
		for _, v := range cpu_info {
			times, _ := strconv.ParseFloat(v, 64)
			cpu_time += times
		}
		return cpu_time / 10000000, nil
	} else {
		return 0.0, errors.New("Get cpu_time failed, os_version error!")
	}
}

func (cm *MEM_Usage_Metric)GetName() string {
	return "MEM_Usage"
}

func (cm *MEM_Usage_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "%", "label": "memory.usage"}}
	total, err := GetMemTotal(option["containerid"], option["os_version"])
	if err != nil {
		log.Error("Error while get total mem:%s", err.Error())
		return sample, err
	}
	mem_use, err := GetMemUse(option["containerid"], option["os_version"])
	if err != nil {
		log.Error("Error while get mem_use:%s", err.Error())
		return sample, err
	}
	limit, _ := strconv.ParseFloat(strings.TrimSpace(total), 64)
	mem_usage := 100.0 * mem_use / limit
	sample[0]["volume"] = strconv.FormatFloat(mem_usage, 'g', -1, 64)

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get memory.usage volume failed!")
	}

	return sample, nil
}

func GetMemTotal(contain_id string, os_version string) (string, error) {
	path, err := util.JoinPath(os_version, "memory", contain_id, "memory.limit_in_bytes")
	if err != nil{
		log.Error("Error while Join memory.limit_in_bytes path:%s", err.Error())
		return "", err
	}
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open memory.limit_in_bytes:%s", err.Error())
		return "", err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file memory.limit_in_bytes:%s", err.Error())
		return "", err
	}

	return string(fd), nil
}

func GetMemUse(contain_id string, os_version string) (float64, error) {
	path, err := util.JoinPath(os_version, "memory", contain_id, "memory.stat")
	if err != nil{
		log.Error("Error while Join memory.stat path:%s", err.Error())
		return 0.0, err
	}
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open memory.stat:%s", err.Error())
		return 0.0, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file memory.stat:%s", err.Error())
		return 0.0, err
	}

	memory_list := strings.Split(string(fd), "\n")
	active_anon_str := strings.Fields(memory_list[6])[1]
	inactive_anon_str := strings.Fields(memory_list[7])[1]
	active_anon, _ := strconv.ParseFloat(active_anon_str, 64)
	inactive_anon, _ := strconv.ParseFloat(inactive_anon_str, 64)

	return active_anon + inactive_anon, nil
}

func (cm *Load_Metric)GetName() string {
	return "Load"
}

func (cm *Load_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "load", "label": "cpu.load"}}
	cpu_set := util.ParseCpuSet(option["cpu_set"])
	cur_load, err := GetLoad(cpu_set)
	if err != nil {
		log.Error("Error while get cur_load:%s", err.Error())
		return sample, err
	}
	pre_load, load_exist := cm.Cache["load"]
	if load_exist {
		var load_one_minute float64 = 60.0
		cur_load = pre_load * math.Exp(-config.ThConf.Deal.Interval.Duration.Seconds() / load_one_minute) + cur_load * (1 - math.Exp(-config.ThConf.Deal.Interval.Duration.Seconds() / load_one_minute))
		sample[0]["volume"] = strconv.FormatFloat(cur_load, 'g', -1, 64)
	}
	cm.Cache["load"] = cur_load

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get load volume failed!")
	}

	return sample, nil
}

func GetLoad(cpu_set []int) (float64, error) {
	sched_debug := "/proc/sched_debug"
	fi, err := os.Open(sched_debug)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open memory.stat:%s", err.Error())
		return 0.0, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file memory.stat:%s", err.Error())
		return 0.0, err
	}

	sched_debug_list := strings.Split(string(fd), "\n")
	start_num := 0
	var cur_load float64 = 0.0
	for _, cpu_no := range cpu_set {
		for i := start_num; i < len(sched_debug_list); i++ {
			if strings.HasPrefix(sched_debug_list[i], "cpu#" + strconv.Itoa(cpu_no)) {
				nr_running, _ := strconv.ParseFloat(strings.Fields(sched_debug_list[i + 1])[2], 64)
				cur_load += nr_running
				start_num = i
				break
			}
		}
	}

	return cur_load, nil
}

func (cm *NET_In_Bytes_Metric)GetName() string {
	return "Net_In_Bytes_Rate"
}

func (cm *NET_In_Bytes_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	samples := []map[string]string{}
	sample := map[string]string{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "B/s"}
	net_io_datas, err := GetNetIO(option["pid"])
	if err != nil {
		log.Error("Error while get net io datas:%s", err.Error())
		return samples, err
	}
	for net_name, net_datas := range net_io_datas {
		receive_bytes_cur, _ := strconv.ParseFloat(strings.Fields(net_datas)[0], 64)
		receive_bytes_pre, receive_bytes_exist := cm.Cache[net_name]
		if receive_bytes_exist {
			receive_bytes_rate := (receive_bytes_cur - receive_bytes_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
			sample["volume"] = strconv.FormatFloat(receive_bytes_rate, 'g', -1, 64)
			sample["label"] = net_name
			samples = append(samples, sample)
		}
		cm.Cache[net_name] = receive_bytes_cur
	}

	if len(samples) == 0 {
		return samples, errors.New("Get net in bytes volume failed!")
	}

	return samples, nil
}

func GetNetIO(pid string) (map[string]string, error) {
	io_datas := map[string]string{}
	path := "/proc/" + pid + "/net/dev"
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open /proc/$pid/net/dev:%s", err.Error())
		return io_datas, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file /proc/$pid/net/dev:%s", err.Error())
		return io_datas, err
	}

	net_io_list := strings.Split(string(fd), "\n")
	for _, net_io_data := range net_io_list[2:] {
		if net_io_data == "" {
			continue
		}
		net_io_datas := strings.Split(net_io_data, ":")
		net_name := strings.TrimSpace(net_io_datas[0])
		if net_name == "lo" {
			continue
		}
		io_datas[net_name] = net_io_datas[1]
	}

	return io_datas, nil
}

func (cm *NET_Out_Bytes_Metric)GetName() string {
	return "Net_Out_Bytes_Rate"
}

func (cm *NET_Out_Bytes_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	samples := []map[string]string{}
	sample := map[string]string{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "B/s"}
	net_io_datas, err := GetNetIO(option["pid"])
	if err != nil {
		log.Error("Error while get net out datas:%s", err.Error())
		return samples, err
	}
	for net_name, net_datas := range net_io_datas {
		transmit_bytes_cur, _ := strconv.ParseFloat(strings.Fields(net_datas)[8], 64)
		transmit_bytes_pre, transmit_bytes_exist := cm.Cache[net_name]
		if transmit_bytes_exist {
			transmit_bytes_rate := (transmit_bytes_cur - transmit_bytes_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
			sample["volume"] = strconv.FormatFloat(transmit_bytes_rate, 'g', -1, 64)
			sample["label"] = net_name
			samples = append(samples, sample)
		}
		cm.Cache[net_name] = transmit_bytes_cur
	}

	if len(samples) == 0 {
		return samples, errors.New("Get net out bytes volume failed!")
	}

	return samples, nil
}

func (cm *Disk_Read_Bytes_Metric)GetName() string {
	return "Disk_Read_Bytes_Rate"
}

func (cm *Disk_Read_Bytes_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "B/s", "label": "disk.io.read.bytes.rate"}}
	device_name, device_name_exist := cm.CacheDm["device_name"]
	if device_name_exist == false {
		var err error
		device_name, err = GetDeviceName(option["containerid"])
		if err != nil {
			log.Error("Error while get device_name:%s", err.Error())
			return sample, err
		}
		cm.CacheDm["device_name"] = device_name
	}
	disk_datas, err := GetDiskIO(device_name)
	if err != nil {
		log.Error("Error while get disk read datas:%s", err.Error())
		return sample, err
	}
	read_bytes_cur, err := strconv.ParseFloat(disk_datas[2], 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat disk read bytes:%s", err.Error())
		return sample, err
	}
	read_bytes_cur *= 512
	read_bytes_pre, read_bytes_exist := cm.Cache["read_bytes"]
	if read_bytes_exist {
		read_bytes_rate := (read_bytes_cur - read_bytes_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatFloat(read_bytes_rate, 'g', -1, 64)
	}
	cm.Cache["read_bytes"] = read_bytes_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get disk read volume failed!")
	}

	return sample, nil
}

func GetDeviceName(con_id string) (string, error) {
	cmd := exec.Command("ls", "-l", "/dev/mapper/docker-" + con_id)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Error("Error while ls -l /dev/mapper/docker-$container_id:%s", err.Error())
		return "", err
	}
	devices := strings.Split(out.String(), "/")
	device_name := strings.Fields(devices[len(devices) - 1])[0]
	return device_name, nil
}

func GetDiskIO(device_name string) ([]string, error) {
	path := "/sys/block/" + device_name + "/stat"
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open %s:%s", path, err.Error())
		return []string{}, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read %s:%s", path, err.Error())
		return []string{}, err
	}

	disk_io_list := strings.Fields(string(fd))
	return disk_io_list, nil
}

func (cm *Disk_Write_Bytes_Metric)GetName() string {
	return "Disk_Write_Bytes_Rate"
}

func (cm *Disk_Write_Bytes_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "B/s", "label": "disk.io.write.bytes.rate"}}
	device_name, device_name_exist := cm.CacheDm["device_name"]
	if device_name_exist == false {
		var err error
		device_name, err = GetDeviceName(option["containerid"])
		if err != nil {
			log.Error("Error while get device_name:%s", err.Error())
			return sample, err
		}
		cm.CacheDm["device_name"] = device_name
	}
	disk_datas, err := GetDiskIO(device_name)
	if err != nil {
		log.Error("Error while get disk Write datas:%s", err.Error())
		return sample, err
	}
	write_bytes_cur, err := strconv.ParseFloat(disk_datas[6], 64)

	if err != nil {
		log.Error("Error while strconv.ParseFloat disk Write bytes:%s", err.Error())
		return sample, err
	}
	write_bytes_cur *= 512.0
	write_bytes_pre, write_bytes_exist := cm.Cache["write_bytes"]
	if write_bytes_exist {
		write_bytes_rate := (write_bytes_cur - write_bytes_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatFloat(write_bytes_rate, 'g', -1, 64)
	}
	cm.Cache["write_bytes"] = write_bytes_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get disk write volume failed!")
	}

	return sample, nil
}

func (cm *Tcp_Conns_Metric)GetName() string {
	return "Tcp_Connections"
}

func (cm *Tcp_Conns_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "connection", "label": "tcp.connections"}}
	connections, err := GetTcpConns(option["pid"])
	if err != nil {
		log.Error("Error while get tcp connections:%s", err.Error())
		return sample, err
	}

	sample[0]["volume"] = strconv.FormatInt(connections, 10)

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get tcp.connections volume failed!")
	}

	return sample, nil
}

func GetTcpConns(pid string) (int64, error) {
	path_ipv4 := "/proc/" + pid + "/net/tcp"
	tcp_nums_ipv4, err := GetTcpNumbers(path_ipv4)
	if err != nil {
		log.Error("Error while get tcp_nums_ipv4:%s", err.Error())
		return 0, err
	}

	path_ipv6 := "/proc/" + pid + "/net/tcp6"
	tcp_nums_ipv6, err := GetTcpNumbers(path_ipv6)
	if err != nil {
		log.Error("Error while get tcp_nums_ipv6:%s", err.Error())
		return 0, err
	}

	return tcp_nums_ipv4+tcp_nums_ipv6, nil
}

func GetTcpNumbers(path string) (int64, error) {
	var tcp_nums int64 = 0
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open %s:%s", path, err.Error())
		return 0, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file %s:%s", path, err.Error())
		return 0, err
	}
	tcp_conn_list := strings.Split(string(fd), "\n")
	for _, tcp_conn := range tcp_conn_list[1:len(tcp_conn_list)-1] {
		if strings.Fields(tcp_conn)[3] == "01" {
			tcp_nums += 1
		}
	}
	return tcp_nums, nil
}

func (cm *Threads_Metric)GetName() string {
	return "Threads"
}

func (cm *Threads_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "thread", "label": "threads"}}
	threads, err := GetLines(option["containerid"], option["os_version"], "tasks")
	if err != nil {
		log.Error("Error while get Threads:%s", err.Error())
		return sample, err
	}

	sample[0]["volume"] = strconv.FormatInt(threads, 10)

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get Threads volume failed!")
	}

	return sample, nil
}

func GetLines(contain_id string, os_version string, file_name string) (int64, error) {
	path, err := util.JoinPath(os_version, "cpuacct", contain_id, file_name)
	if err != nil{
		log.Error("Error while Join %s path:%s", file_name, err.Error())
		return 0, err
	}
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open %s:%s", file_name, err.Error())
		return 0, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file %s:%s", file_name, err.Error())
		return 0, err
	}
	lines := strings.Split(string(fd), "\n")

	return int64(len(lines)), nil
}

func (cm *Processes_Metric)GetName() string {
	return "Processes"
}

func (cm *Processes_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "process", "label": "processes"}}
	processs, err := GetLines(option["containerid"], option["os_version"], "cgroup.procs")
	if err != nil {
		log.Error("Error while get Processes:%s", err.Error())
		return sample, err
	}

	sample[0]["volume"] = strconv.FormatInt(processs, 10)

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get Processes volume failed!")
	}

	return sample, nil
}
