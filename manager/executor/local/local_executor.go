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

package local

import (
	"errors"
	"strings"
	"os/exec"
	"time"

	"thor/manager"
	"thor/log"
	"thor/util"
)

var (
	DEAL_TYPE = "executor"
	DEAL_NAME = "local"
)

func init() {
	manager.RegisterDeal(DEAL_TYPE, DEAL_NAME, Init)
}

func Init(options map[string]string) (manager.Deal, error) {

	uuid, ok := options["uuid"]

	cmd, ok := options["cmd"]
	if !ok || cmd == "" {
		return nil, errors.New("Got no CMD")
	}
	args, ok := options["args"]

	return &LocalExec{
		Uuid: uuid,
		Cmd: cmd,
		Args: args,
		UcMap: map[string]string{},
	}, nil
}

type LocalExec struct {
	// cmd
	Cmd   string

	// args
	Args  string

	// uuid
	Uuid  string

	// uuid -> containerid
	UcMap map[string]string
}

func (le *LocalExec)Run() (map[string][]map[string]string, error) {

	result := make(map[string][]map[string]string)

	args := strings.Split(le.Args, " ")

	var eargs []string
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg != "" {
			eargs = append(eargs, arg)
		}
	}

	// container
	cmd := le.Cmd
	if le.Uuid != "" {
		// ls -l -h /home   ->
		// docker exec xxx ls -l -h /home

		cid, ok := le.UcMap[le.Uuid]
		if !ok {
			//get containerid
			coninfo, err := util.GetContainerIdByUUID(le.Uuid)
			if err == nil {
				cid = coninfo.Id
				le.UcMap[le.Uuid] = coninfo.Id
			} else {
				return map[string][]map[string]string{}, err
			}
		}

		eargs = append(append([]string{"exec", cid}, le.Cmd), eargs...)

		cmd = "docker"
	}

	res, err := le.Exec(cmd, eargs)
	if err != nil {
		return map[string][]map[string]string{}, err
	}

	result[le.Cmd] = []map[string]string{res}

	return result, nil
}

func (le *LocalExec)GetDealType() string {
	return DEAL_TYPE
}

// Get the cmd.
func (le *LocalExec)GetCmd() string {
	return le.Cmd
}

// Run cmd.
func (le *LocalExec)Exec(cmd string, args []string) (map[string]string, error) {

	command := exec.Command(cmd, args...)

	output, err := command.Output()
	if err != nil {
		res := map[string]string{
			"volume": err.Error(),
			"timestamp": time.Now().String(),
		}

		log.Warn("Failed to exec CMD %s ARGS %+v: %s", cmd, args, err.Error())
		return res, nil
	}

	res := map[string]string{
		"volume": string(output),
		"timestamp": time.Now().String(),
	}

	return res, nil
}