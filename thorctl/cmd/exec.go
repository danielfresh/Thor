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
	"strings"
	"encoding/json"

	"thorctl/lib"
)

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec",
	Short: "Run a command in a remote running container",
	Long: `Run a command in a remote running container.
For example:

thorctl -H 127.0.0.1 -P 9898 exec -c 10 -i 2s -e "ls /" 6R574YU`,
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

		conn, err := net.Dial("tcp", host + ":"+ port)
		if err != nil {
			fmt.Println("dial error:", err)
			os.Exit(-1)
		}

		command, err := cmd.Flags().GetString("command")
		if err != nil {
			fmt.Println("Error when get command")
			os.Exit(1)
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

		cmdstr := strings.SplitN(command, " ", 2)
		cmdname := ""
		cmdargs := ""
		switch len(cmdstr) {
		case 1:
			cmdname = strings.TrimSpace(cmdstr[0])
			if cmdname == "" {
				fmt.Println(`Pl specify command with option -e`)
				os.Exit(1)
			}
			cmdargs = ""
		case 2:
			cmdname = strings.TrimSpace(cmdstr[0])
			if cmdname == "" {
				fmt.Println(`Pl specify command with option -e`)
				os.Exit(1)
			}
			cmdargs = strings.TrimSpace(cmdstr[1])
		default:
			fmt.Println("Error when parse command: ", command)
			os.Exit(-1)
		}

		target := ""
		if len(args) > 0 {
			target = args[0]
		}

		err = lib.SendRequest(conn, "executor", host, interval, count,
			map[string]string{"uuid": target, "cmd": cmdname, "args": cmdargs})

		if err != nil {
			fmt.Println("Error when SendRequest", err)
			os.Exit(1)
		}

		lib.RecvResponse(conn, count, interval, func(data []byte) error {

			status := CmdResult{}

			err = json.Unmarshal(data, &status)
			if err != nil {
				fmt.Println("Error when Unmarshal: ", err)
			}

			clear := false
			if count != 1 {
				clear = true
			}

			content := ""
			for k, v := range status {

				if k == "Succ" {
					succ, ok := v[0]["success"]
					if !ok || succ == "false" {
						lib.Display("Command: --\t\nTimestamp: --\t\nResult:\n--\t\n\n", "", clear)
						return nil
					}

					continue
				}

				result := ""
				format := "Command: %s\t\nTimestamp: %s\t\nResult:\n%s\t\n\n"
				str := ""
				if err != nil {
					str = "--"
				} else {
					str = v[0]["volume"]
				}
				ts := v[0]["timestamp"]
				result = fmt.Sprintf(format, k, ts, str)

				content += result
			}
			lib.Display(content, "", clear)
			return nil
		})
	},
}

func init() {
	RootCmd.AddCommand(execCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// execCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// execCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	execCmd.Flags().StringP("command", "e", "", "The command to be executed")
	execCmd.Flags().StringP("interval", "i", "2s", "The amount of time in seconds between each report")
	execCmd.Flags().IntP("count", "c", 0, "The number of reports generated at interval seconds apart")
}
