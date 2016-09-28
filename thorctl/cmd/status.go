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

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"net"
	"encoding/json"
	"strconv"

	"thorctl/lib"
)

const (
	CONTAINER_ID_LEN = 8
)

func fmtMeter(status ContainerStatus, target string) (content string) {

	// CONTAINER  CPU % MEM %Load\tNetIO(In/Out)\tDiskIO(In/Out)\n

	cid := target
	if len(target) > CONTAINER_ID_LEN {
		cid = target[:CONTAINER_ID_LEN]
	}

	format := "%s\t%.2f\t%.2f\t%.2f\t%.2f / %.2f\t%.2f / %.2f\n"
	errStr := 0.0
	content = fmt.Sprintf(format, cid + "(ERR)", errStr, errStr, errStr, errStr, errStr, errStr, errStr)

	succ, ok := status.Succ[0]["success"]
	if !ok || succ == "false" {
		return
	}

	if status.err != nil {
		return
	} else {
		var err error
		//CpuUsage
		var cpu float64 = 0.00
		if len(status.CpuUsage) == 0 {
			cpu = errStr
		} else {
			cpu, err = strconv.ParseFloat(status.CpuUsage[0].Volume, 64)
			if err != nil {
				cpu = errStr
			}
		}

		//MemUsage
		var mem float64 = 0.00
		if len(status.MEM_Usage) == 0 {
			mem = errStr
		} else {
			mem, err = strconv.ParseFloat(status.MEM_Usage[0].Volume, 64)
			if err != nil {
				mem = errStr
			}
		}

		//Load
		var load float64 = 0.00
		if len(status.Load) == 0 {
			load = errStr
		} else {
			load, err = strconv.ParseFloat(status.Load[0].Volume, 64)
			if err != nil {
				load = errStr
			}
		}

		//Net_In_Bytes_Rate
		var netInTotal float64 = 0.0
		for _, netin := range status.Net_In_Bytes_Rate {
			if netin.Volume != "" {
				volume, err := strconv.ParseFloat(netin.Volume, 64)
				if err != nil {
					fmt.Printf("Error when parse netin %s: %s\n", netin.Volume, err.Error())
					netInTotal = 0.0
					break
				}

				netInTotal += volume
			} else {
				netInTotal = 0.0
				break
			}
		}

		netInTotal = netInTotal / 1024.00 / 1024.00

		//Net_Out_Bytes_Rate
		var netOutTotal float64 = 0.0
		for _, netout := range status.Net_Out_Bytes_Rate {
			if netout.Volume != "" {
				volume, err := strconv.ParseFloat(netout.Volume, 64)
				if err != nil {
					fmt.Printf("Error when parse netout %s: %s\n", netout.Volume, err.Error())
					netOutTotal = 0.0
					break
				}

				netOutTotal += volume
			} else {
				netOutTotal = 0.0
				break
			}
		}

		netOutTotal = netOutTotal / 1024.00 / 1024.00

		//Disk_Read_Bytes_Rate
		var diskReadTotal float64 = 0.0
		for _, diskread := range status.Disk_Read_Bytes_Rate {
			if diskread.Volume != "" {
				volume, err := strconv.ParseFloat(diskread.Volume, 64)
				if err != nil {
					fmt.Printf("Error when parse disk read %s: %s\n", diskread.Volume, err.Error())
					diskReadTotal = 0.0
					break
				}

				diskReadTotal += volume
			} else {
				diskReadTotal = 0.0
				break
			}
		}

		diskReadTotal = diskReadTotal / 1024.00 / 1024.00

		//Disk_Write_Bytes_Rate
		var disWriteTotal float64 = 0.0
		for _, diskwrite := range status.Disk_Write_Bytes_Rate {
			if diskwrite.Volume != "" {
				volume, err := strconv.ParseFloat(diskwrite.Volume, 64)
				if err != nil {
					fmt.Printf("Error when parse disk write %s: %s\n", diskwrite.Volume, err.Error())
					disWriteTotal = 0.0
					break
				}

				disWriteTotal += volume
			} else {
				disWriteTotal = 0.0
				break
			}
		}

		disWriteTotal = disWriteTotal / 1024.00 / 1024.00

		content = fmt.Sprintf(format, cid, cpu, mem, load, netInTotal, netOutTotal, diskReadTotal, disWriteTotal)
	}

	return
}

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display a live stream of container resource usage statistics",
	Long: `Display a live stream of container resource usage statistics.
For example:
thorctl -H 127.0.0.1 -P 9898 status 6R574YU`,
	Run: func(cmd *cobra.Command, args []string) {

		host, err := cmd.Flags().GetString("host")
		if err != nil {
			fmt.Println("Error when get host")
			os.Exit(1)
		}

		port, err := cmd.Flags().GetString("port")
		if err != nil {
			fmt.Println("Error when get port")
			os.Exit(1)
		}

		conn, err := net.Dial("tcp", host + ":" + port)
		if err != nil {
			fmt.Println("dial error:", err)
			os.Exit(-1)
		}

		interval, err := cmd.Flags().GetString("interval")
		if err != nil {
			fmt.Println("Error when get interval")
			os.Exit(1)
		}

		count, err := cmd.Flags().GetInt("count")
		if err != nil {
			fmt.Println("Error when get count")
			os.Exit(1)
		}

		idcount, err := cmd.Flags().GetCount("not-container-id")
		if err != nil {
			fmt.Println("Error when get containerId")
			os.Exit(1)
		}

		if len(args) <= 0 {
			fmt.Println("You must specify the resource to get.")
			os.Exit(1)
		}

		target := args[0]

		var content map[string]string
		if idcount == 0 {
			content = map[string]string{
				"containerid": target,
				"metrics": `["CPU_Usage", "MEM_Usage", "Load", "Net_In_Bytes_Rate", "Net_Out_Bytes_Rate", "Disk_Read_Bytes_Rate", "Disk_Write_Bytes_Rate"]`,
			}
		} else {
			content = map[string]string{
				"uuid": target,
				"metrics": `["CPU_Usage", "MEM_Usage", "Load", "Net_In_Bytes_Rate", "Net_Out_Bytes_Rate", "Disk_Read_Bytes_Rate", "Disk_Write_Bytes_Rate"]`,
			}
		}

		err = lib.SendRequest(conn, "collector", host, interval, count, content)
		if err != nil {
			fmt.Println("Error when SendRequest", err)
			os.Exit(1)
		}

		lib.RecvResponse(conn, count, interval, func(data []byte) error {

			status := ContainerStatus{}

			err = json.Unmarshal(data, &status)
			if err != nil {
				fmt.Println("Error when Unmarshal", err)
				status.err = err
			}

			clear := false
			if count != 1 {
				clear = true
			}

			header := "CONTAINER\tCPU %\tMEM %\tLoad\tNetIO(I/O)\tDiskIO(I/O)\n"
			content := fmtMeter(status, target)

			lib.Display(content, header, clear)

			return nil
		})

		return
	},
}

func init() {
	RootCmd.AddCommand(statusCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// statusCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	statusCmd.Flags().CountP("not-container-id", "d", "If the input is not a container id")
	statusCmd.Flags().StringP("interval", "i", "2s", "The amount of time in seconds between each report")
	statusCmd.Flags().IntP("count", "c", 0, "The number of reports generated at interval seconds apart")

}

