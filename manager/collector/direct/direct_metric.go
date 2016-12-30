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
	RegisterMetric("Net_In_Packets_Rate", InitMetricNetInPackets)
	RegisterMetric("Net_Out_Packets_Rate", InitMetricNetOutPackets)
	RegisterMetric("Disk_Read_Bytes_Rate", InitMetricDiskRead)
	RegisterMetric("Disk_Write_Bytes_Rate", InitMetricDiskWrite)
	RegisterMetric("Disk_Read_Requests_Rate", InitMetricDiskReadRequests)
	RegisterMetric("Disk_Write_Requests_Rate", InitMetricDiskWriteRequests)
	RegisterMetric("Disk_IO_Util", InitMetricDiskIOUtil)
	RegisterMetric("Tcp_Connections", InitMetricTcpConns)
	RegisterMetric("Threads", InitMetricThreads)
	RegisterMetric("Processes", InitMetricProcesses)
	RegisterMetric("Ip_InReceives", InitMetricIpInReceives)
	RegisterMetric("Ip_InDiscards", InitMetricIpInDiscards)
	RegisterMetric("Tcp_ActiveOpens", InitMetricTcpActiveOpens)
	RegisterMetric("Tcp_InErrs", InitMetricTcpInErrs)
	RegisterMetric("Tcp_RetransSegs", InitMetricTcpRetransSegs)
	RegisterMetric("Tcp_InSegs", InitMetricTcpInSegs)
	RegisterMetric("Tcp_OutSegs", InitMetricTcpOutSegs)
	RegisterMetric("FD", InitMetricFD)
	RegisterMetric("MemoryFailcnt", InitMetricMemoryFailcnt)
	RegisterMetric("MemorySwap", InitMetricMemorySwap)
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

func InitMetricNetInPackets() collector.Metric {
	return &NET_In_Packets_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricNetOutPackets() collector.Metric {
	return &NET_Out_Packets_Metric{
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

func InitMetricDiskReadRequests() collector.Metric {
	return &Disk_Read_Requests_Metric{
		Cache: make(map[string]float64),
		CacheDm: make(map[string]string),
	}
}

func InitMetricDiskWriteRequests() collector.Metric {
	return &Disk_Write_Requests_Metric{
		Cache: make(map[string]float64),
		CacheDm: make(map[string]string),
	}
}

func InitMetricDiskIOUtil() collector.Metric {
	return &Disk_IO_Util_Metric{
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

func InitMetricIpInReceives() collector.Metric {
	return &Ip_InReceives_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricIpInDiscards() collector.Metric {
	return &Ip_InDiscards_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricTcpActiveOpens() collector.Metric {
	return &Tcp_ActiveOpens_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricTcpInErrs() collector.Metric {
	return &Tcp_InErrs_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricTcpRetransSegs() collector.Metric {
	return &Tcp_RetransSegs_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricTcpInSegs() collector.Metric {
	return &Tcp_InSegs_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricTcpOutSegs() collector.Metric {
	return &Tcp_OutSegs_Metric{
		Cache: make(map[string]float64),
	}
}

func InitMetricFD() collector.Metric {
	return &FD_Metric{}
}

func InitMetricMemoryFailcnt() collector.Metric {
	return &Memory_Failcnt_Metric{
		Cache: make(map[string]int64),
	}
}

func InitMetricMemorySwap() collector.Metric {
	return &Memory_Swap_Metric{}
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

type NET_In_Packets_Metric struct {
	Cache map[string]float64
}

type NET_Out_Packets_Metric struct {
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

type Disk_Read_Requests_Metric struct {
	Cache   map[string]float64
	CacheDm map[string]string
}

type Disk_Write_Requests_Metric struct {
	Cache   map[string]float64
	CacheDm map[string]string
}

type Disk_IO_Util_Metric struct {
	Cache   map[string]float64
	CacheDm map[string]string
}

type Tcp_Conns_Metric struct {

}

type Threads_Metric struct {

}

type Processes_Metric struct {

}

type Ip_InReceives_Metric struct {
	Cache map[string]float64
}

type Ip_InDiscards_Metric struct {
	Cache map[string]float64
}

type Tcp_ActiveOpens_Metric struct {
	Cache map[string]float64
}

type Tcp_InErrs_Metric struct {
	Cache map[string]float64
}

type Tcp_RetransSegs_Metric struct {
	Cache map[string]float64
}

type Tcp_InSegs_Metric struct {
	Cache map[string]float64
}

type Tcp_OutSegs_Metric struct {
	Cache map[string]float64
}

type FD_Metric struct {

}

type Memory_Failcnt_Metric struct {
	Cache map[string]int64
}

type Memory_Swap_Metric struct {

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
	mem_stat, err := GetMemStat(option["containerid"], option["os_version"])
	if err != nil {
		log.Error("Error while get mem_stat in MEM_Usage_Metric:%s", err.Error())
		return sample, err
	}
	active_anon_str := strings.Fields(mem_stat[6])[1]
	inactive_anon_str := strings.Fields(mem_stat[7])[1]
	active_anon, _ := strconv.ParseFloat(active_anon_str, 64)
	inactive_anon, _ := strconv.ParseFloat(inactive_anon_str, 64)
	mem_use := active_anon + inactive_anon

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

func GetMemStat(contain_id string, os_version string) ([]string, error) {
	path, err := util.JoinPath(os_version, "memory", contain_id, "memory.stat")
	if err != nil{
		log.Error("Error while Join memory.stat path:%s", err.Error())
		return []string{}, err
	}
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open memory.stat:%s", err.Error())
		return []string{}, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file memory.stat:%s", err.Error())
		return []string{}, err
	}

	memory_list := strings.Split(string(fd), "\n")
	return memory_list, nil
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
		log.Error("Error while get net in datas:%s", err.Error())
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
		log.Error("Error while open /proc/%s/net/dev:%s", pid, err.Error())
		return io_datas, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file /proc/%s/net/dev:%s", pid, err.Error())
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

func (cm *NET_In_Packets_Metric)GetName() string {
	return "Net_In_Packets_Rate"
}

func (cm *NET_In_Packets_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	samples := []map[string]string{}
	sample := map[string]string{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "packet/s"}
	net_io_datas, err := GetNetIO(option["pid"])
	if err != nil {
		log.Error("Error while get net in packets datas:%s", err.Error())
		return samples, err
	}
	for net_name, net_datas := range net_io_datas {
		receive_packets_cur, _ := strconv.ParseFloat(strings.Fields(net_datas)[1], 64)
		receive_packets_pre, receive_packets_exist := cm.Cache[net_name]
		if receive_packets_exist {
			receive_packets_rate := (receive_packets_cur - receive_packets_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
			sample["volume"] = strconv.FormatFloat(receive_packets_rate, 'g', -1, 64)
			sample["label"] = net_name
			samples = append(samples, sample)
		}
		cm.Cache[net_name] = receive_packets_cur
	}

	if len(samples) == 0 {
		return samples, errors.New("Get net in packets volume failed!")
	}

	return samples, nil
}

func (cm *NET_Out_Packets_Metric)GetName() string {
	return "Net_Out_Packets_Rate"
}

func (cm *NET_Out_Packets_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	samples := []map[string]string{}
	sample := map[string]string{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "packet/s"}
	net_io_datas, err := GetNetIO(option["pid"])
	if err != nil {
		log.Error("Error while get net out packets datas:%s", err.Error())
		return samples, err
	}
	for net_name, net_datas := range net_io_datas {
		transmit_packets_cur, _ := strconv.ParseFloat(strings.Fields(net_datas)[9], 64)
		transmit_packets_pre, transmit_packets_exist := cm.Cache[net_name]
		if transmit_packets_exist {
			transmit_packets_rate := (transmit_packets_cur - transmit_packets_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
			sample["volume"] = strconv.FormatFloat(transmit_packets_rate, 'g', -1, 64)
			sample["label"] = net_name
			samples = append(samples, sample)
		}
		cm.Cache[net_name] = transmit_packets_cur
	}

	if len(samples) == 0 {
		return samples, errors.New("Get net out packets volume failed!")
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

func (cm *Disk_Read_Requests_Metric)GetName() string {
	return "Disk_Read_Requests_Rate"
}

func (cm *Disk_Read_Requests_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "request/s", "label": "disk.io.read.requests.rate"}}
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
		log.Error("Error while get disk read request datas:%s", err.Error())
		return sample, err
	}
	read_requests_cur, err := strconv.ParseFloat(disk_datas[0], 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat disk read requests:%s", err.Error())
		return sample, err
	}
	read_requests_pre, read_requests_exist := cm.Cache["read_requests"]
	if read_requests_exist {
		read_requests_rate := (read_requests_cur - read_requests_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatFloat(read_requests_rate, 'g', -1, 64)
	}
	cm.Cache["read_requests"] = read_requests_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get disk read request volume failed!")
	}

	return sample, nil
}

func (cm *Disk_Write_Requests_Metric)GetName() string {
	return "Disk_Write_Requests_Rate"
}

func (cm *Disk_Write_Requests_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "request/s", "label": "disk.io.write.requests.rate"}}
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
		log.Error("Error while get disk Write request datas:%s", err.Error())
		return sample, err
	}
	write_requests_cur, err := strconv.ParseFloat(disk_datas[4], 64)

	if err != nil {
		log.Error("Error while strconv.ParseFloat disk Write requests:%s", err.Error())
		return sample, err
	}
	write_requests_pre, write_requests_exist := cm.Cache["write_requests"]
	if write_requests_exist {
		write_requests_rate := (write_requests_cur - write_requests_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatFloat(write_requests_rate, 'g', -1, 64)
	}
	cm.Cache["write_requests"] = write_requests_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get disk write request volume failed!")
	}

	return sample, nil
}

func (cm *Disk_IO_Util_Metric)GetName() string {
	return "Disk_IO_Util"
}

func (cm *Disk_IO_Util_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "%", "label": "disk.io.util"}}
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
	disk_io_cur, err := strconv.ParseFloat(disk_datas[9], 64)

	if err != nil {
		log.Error("Error while strconv.ParseFloat disk_io:%s", err.Error())
		return sample, err
	}
	disk_io_cur /= 1000.0
	disk_io_pre, disk_io_exist := cm.Cache["disk_io"]
	if disk_io_exist {
		disk_io_util := (disk_io_cur - disk_io_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatFloat(disk_io_util, 'g', -1, 64)
	}
	cm.Cache["disk_io"] = disk_io_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get disk_io volume failed!")
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
	path, err := util.JoinPath(option["os_version"], "cpuacct", option["containerid"], "tasks")
	if err != nil{
		log.Error("Error while Join threads file:%s", err.Error())
		return sample, err
	}
	threads, err := GetLines(path)
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

func GetLines(path string) (int64, error) {
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
	lines := strings.Split(string(fd), "\n")

	return int64(len(lines)), nil
}

func (cm *Processes_Metric)GetName() string {
	return "Processes"
}

func (cm *Processes_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "process", "label": "processes"}}
	path, err := util.JoinPath(option["os_version"], "cpuacct", option["containerid"], "cgroup.procs")
	if err != nil{
		log.Error("Error while Join Processes file:%s", err.Error())
		return sample, err
	}
	processs, err := GetLines(path)
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

func (cm *Ip_InReceives_Metric)GetName() string {
	return "Ip_InReceives"
}

func (cm *Ip_InReceives_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "packet/s", "label": "ip.inreceives.rate"}}
	snmp_datas, err := GetSnmp(option["pid"])
	if err != nil {
		log.Error("Error while get snmp datas:%s", err.Error())
		return sample, err
	}
	ip_inreceives, err := ParseSnmpData(snmp_datas, "Ip", "InReceives")
	if err != nil {
		log.Error("Error while get ParseSnmpData:%s", err.Error())
		return sample, err
	}
	ip_inreceives_cur, err := strconv.ParseFloat(ip_inreceives, 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat ip_inreceives:%s", err.Error())
		return sample, err
	}

	ip_inreceives_pre, ip_inreceives_exist := cm.Cache["ip_inreceives"]
	if ip_inreceives_exist {
		ip_inreceives_rate := (ip_inreceives_cur - ip_inreceives_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatInt(int64(ip_inreceives_rate), 10)
	}
	cm.Cache["ip_inreceives"] = ip_inreceives_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get ip_inreceives volume failed!")
	}

	return sample, nil
}

func GetSnmp(pid string) ([]string, error) {
	io_datas := []string{}
	path := "/proc/" + pid + "/net/snmp"
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open /proc/%s/net/snmp:%s", pid, err.Error())
		return io_datas, err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file /proc/%s/net/snmp:%s", pid, err.Error())
		return io_datas, err
	}

	snmp_datas := strings.Split(string(fd), "\n")
	return  snmp_datas, nil
}

func ParseSnmpData(snmp_datas []string, packet_type string, packet_info string) (string, error) {
	packet_type_num := 0
	packet_info_num := 0
	for num, snmp_line := range snmp_datas {
		if strings.HasPrefix(snmp_line, packet_type) {
			packet_type_num = num
			break
		}
	}
	snmp_data_list := strings.Fields(snmp_datas[packet_type_num])
	for num, info := range snmp_data_list {
		if info == packet_info {
			packet_info_num = num
			break
		}
	}
	packet_info_data := strings.Fields(snmp_datas[packet_type_num+1])[packet_info_num]
	return packet_info_data, nil
}

func (cm *Ip_InDiscards_Metric)GetName() string {
	return "Ip_InDiscards"
}

func (cm *Ip_InDiscards_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "packet/s", "label": "ip.indiscards.rate"}}
	snmp_datas, err := GetSnmp(option["pid"])
	if err != nil {
		log.Error("Error while get snmp datas:%s", err.Error())
		return sample, err
	}
	ip_indiscards, err := ParseSnmpData(snmp_datas, "Ip", "InDiscards")
	if err != nil {
		log.Error("Error while ParseSnmpData:%s", err.Error())
		return sample, err
	}
	ip_indiscards_cur, err := strconv.ParseFloat(ip_indiscards, 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat InDiscards:%s", err.Error())
		return sample, err
	}

	ip_indiscards_pre, ip_indiscards_exist := cm.Cache["ip_indiscards"]
	if ip_indiscards_exist {
		ip_indiscards_rate := (ip_indiscards_cur - ip_indiscards_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatInt(int64(ip_indiscards_rate), 10)
	}
	cm.Cache["ip_indiscards"] = ip_indiscards_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get ip_indiscards volume failed!")
	}

	return sample, nil
}

func (cm *Tcp_ActiveOpens_Metric)GetName() string {
	return "Tcp_ActiveOpens"
}

func (cm *Tcp_ActiveOpens_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "segment/s", "label": "tcp.activeopens.rate"}}
	snmp_datas, err := GetSnmp(option["pid"])
	if err != nil {
		log.Error("Error while get snmp datas:%s", err.Error())
		return sample, err
	}
	tcp_activeopens, err := ParseSnmpData(snmp_datas, "Tcp", "ActiveOpens")
	if err != nil {
		log.Error("Error while ParseSnmpData:%s", err.Error())
		return sample, err
	}
	tcp_activeopens_cur, err := strconv.ParseFloat(tcp_activeopens, 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat tcp_activeopens:%s", err.Error())
		return sample, err
	}

	tcp_activeopens_pre, tcp_activeopens_exist := cm.Cache["tcp_activeopens"]
	if tcp_activeopens_exist {
		tcp_activeopens_rate := (tcp_activeopens_cur - tcp_activeopens_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatInt(int64(tcp_activeopens_rate), 10)
	}
	cm.Cache["tcp_activeopens"] = tcp_activeopens_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get tcp_activeopens volume failed!")
	}

	return sample, nil
}

func (cm *Tcp_InErrs_Metric)GetName() string {
	return "Tcp_InErrs"
}

func (cm *Tcp_InErrs_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "segment/s", "label": "tcp.inerrs.rate"}}
	snmp_datas, err := GetSnmp(option["pid"])
	if err != nil {
		log.Error("Error while get snmp datas:%s", err.Error())
		return sample, err
	}
	tcp_inerrs, err := ParseSnmpData(snmp_datas, "Tcp", "InErrs")
	if err != nil {
		log.Error("Error while ParseSnmpData:%s", err.Error())
		return sample, err
	}
	tcp_inerrs_cur, err := strconv.ParseFloat(tcp_inerrs, 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat tcp_inerrs:%s", err.Error())
		return sample, err
	}

	tcp_inerrs_pre, tcp_inerrs_exist := cm.Cache["tcp_inerrs"]
	if tcp_inerrs_exist {
		tcp_inerrs_rate := (tcp_inerrs_cur - tcp_inerrs_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatInt(int64(tcp_inerrs_rate), 10)
	}
	cm.Cache["tcp_inerrs"] = tcp_inerrs_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get tcp_inerrs volume failed!")
	}

	return sample, nil
}

func (cm *Tcp_RetransSegs_Metric)GetName() string {
	return "Tcp_RetransSegs"
}

func (cm *Tcp_RetransSegs_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "segment/s", "label": "tcp.retranssegs.rate"}}
	snmp_datas, err := GetSnmp(option["pid"])
	if err != nil {
		log.Error("Error while get snmp datas:%s", err.Error())
		return sample, err
	}
	tcp_retranssegs, err := ParseSnmpData(snmp_datas, "Tcp", "RetransSegs")
	if err != nil {
		log.Error("Error while ParseSnmpData:%s", err.Error())
		return sample, err
	}
	tcp_retranssegs_cur, err := strconv.ParseFloat(tcp_retranssegs, 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat tcp_retranssegs:%s", err.Error())
		return sample, err
	}

	tcp_retranssegs_pre, tcp_retranssegs_exist := cm.Cache["tcp_retranssegs"]
	if tcp_retranssegs_exist {
		tcp_retranssegs_rate := (tcp_retranssegs_cur - tcp_retranssegs_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatInt(int64(tcp_retranssegs_rate), 10)
	}
	cm.Cache["tcp_retranssegs"] = tcp_retranssegs_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get tcp_retranssegs volume failed!")
	}

	return sample, nil
}

func (cm *Tcp_InSegs_Metric)GetName() string {
	return "Tcp_InSegs"
}

func (cm *Tcp_InSegs_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "segment/s", "label": "tcp.insegs.rate"}}
	snmp_datas, err := GetSnmp(option["pid"])
	if err != nil {
		log.Error("Error while get snmp datas:%s", err.Error())
		return sample, err
	}
	tcp_insegs, err := ParseSnmpData(snmp_datas, "Tcp", "InSegs")
	if err != nil {
		log.Error("Error while ParseSnmpData:%s", err.Error())
		return sample, err
	}
	tcp_insegs_cur, err := strconv.ParseFloat(tcp_insegs, 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat tcp_insegs:%s", err.Error())
		return sample, err
	}

	tcp_insegs_pre, tcp_insegs_exist := cm.Cache["tcp_insegs"]
	if tcp_insegs_exist {
		tcp_insegs_rate := (tcp_insegs_cur - tcp_insegs_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatInt(int64(tcp_insegs_rate), 10)
	}
	cm.Cache["tcp_insegs"] = tcp_insegs_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get tcp_insegs volume failed!")
	}

	return sample, nil
}

func (cm *Tcp_OutSegs_Metric)GetName() string {
	return "Tcp_OutSegs"
}

func (cm *Tcp_OutSegs_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "segment/s", "label": "tcp.outsegs.rate"}}
	snmp_datas, err := GetSnmp(option["pid"])
	if err != nil {
		log.Error("Error while get snmp datas:%s", err.Error())
		return sample, err
	}
	tcp_outsegs, err := ParseSnmpData(snmp_datas, "Tcp", "OutSegs")
	if err != nil {
		log.Error("Error while ParseSnmpData:%s", err.Error())
		return sample, err
	}
	tcp_outsegs_cur, err := strconv.ParseFloat(tcp_outsegs, 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat tcp_outsegs:%s", err.Error())
		return sample, err
	}

	tcp_outsegs_pre, tcp_outsegs_exist := cm.Cache["tcp_outsegs"]
	if tcp_outsegs_exist {
		tcp_outsegs_rate := (tcp_outsegs_cur - tcp_outsegs_pre) / config.ThConf.Deal.Interval.Duration.Seconds()
		sample[0]["volume"] = strconv.FormatInt(int64(tcp_outsegs_rate), 10)
	}
	cm.Cache["tcp_outsegs"] = tcp_outsegs_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get tcp_outsegs volume failed!")
	}

	return sample, nil
}

func (cm *FD_Metric)GetName() string {
	return "FD"
}

func (cm *FD_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "fd", "label": "fd.numbers"}}
	fd, err := GetFD(option["pid"])
	if err != nil {
		log.Error("Error while get FD:%s", err.Error())
		return sample, err
	}

	sample[0]["volume"] = strconv.FormatInt(fd, 10)

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get FD volume failed!")
	}

	return sample, nil
}

func GetFD(pid string) (int64, error) {
	dir_path := "/proc/" + pid + "/fd/"
	files, err := ioutil.ReadDir(dir_path)
	if err != nil {
		log.Error("Error while ReadDir:%s, %s", dir_path, err.Error())
		return 0, err
	}
	return int64(len(files)), nil
}

func (cm *Memory_Failcnt_Metric)GetName() string {
	return "MemoryFailcnt"
}

func (cm *Memory_Failcnt_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "count", "label": "memory.memsw.failcnt"}}
	path, err := util.JoinPath(option["os_version"], "memory", option["containerid"], "memory.memsw.failcnt")
	if err != nil{
		log.Error("Error while Join MemoryFailcnt file:%s", err.Error())
		return sample, err
	}
	memory_failcnts, err := GetMemoryFailcnt(path)
	if err != nil {
		log.Error("Error while get MemoryFailcnt:%s", err.Error())
		return sample, err
	}
	memory_failcnt_cur, err := strconv.ParseInt(strings.TrimSpace(memory_failcnts), 10, 64)
	if err != nil {
		log.Error("Error while strconv.ParseFloat MemoryFailcnt:%s", err.Error())
		return sample, err
	}

	memory_failcnt_pre, memory_failcnt_exist := cm.Cache["memory_failcnt"]
	if memory_failcnt_exist {
		memory_failcnt := memory_failcnt_cur - memory_failcnt_pre
		sample[0]["volume"] = strconv.FormatInt(memory_failcnt, 10)
	}
	cm.Cache["memory_failcnt"] = memory_failcnt_cur

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get MemoryFailcnt volume failed!")
	}

	return sample, nil
}

func GetMemoryFailcnt(path string) (string, error) {
	fi, err := os.Open(path)
	defer fi.Close()
	if err != nil {
		log.Error("Error while open %s%s", path, err.Error())
		return "", err
	}
	fd, err := ioutil.ReadAll(fi)
	if err != nil {
		log.Error("Error while read file %s:%s", path, err.Error())
		return "", err
	}

	return  string(fd), nil
}

func (cm *Memory_Swap_Metric)GetName() string {
	return "MemorySwap"
}

func (cm *Memory_Swap_Metric)Collect(option map[string]string) ([]map[string]string, error) {
	sample := []map[string]string{{"timestamp": strconv.FormatInt(time.Now().Unix(), 10), "unit": "MB", "label": "memory.swap"}}
	mem_stat, err := GetMemStat(option["containerid"], option["os_version"])
	if err != nil {
		log.Error("Error while get mem_stat in MEM_Usage_Metric:%s", err.Error())
		return sample, err
	}
	swap_str := strings.Fields(mem_stat[5])[1]
	memory_swap, _ := strconv.ParseInt(swap_str, 10, 64)
	memory_swap_MB := memory_swap/1024/1024

	sample[0]["volume"] = strconv.FormatInt(memory_swap_MB, 10)

	_, volume_exists := sample[0]["volume"]
	if !volume_exists {
		return sample, errors.New("Get MemSwap volume failed!")
	}

	return sample, nil
}