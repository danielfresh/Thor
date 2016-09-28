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

package main

import (
	"net"
	"fmt"

	_ "thor/manager"
	_ "thor/manager/register"
	"thor/manager"
	"thor/log"
	conf "thor/config"
)

const (
	OUTPUT_DRV = "file"
)

func init() {
	conf.LoadConfig(conf.DEFAULT_CONF)

	log_args := fmt.Sprintf("{\"filename\": \"%s\", \"level\": %d}",
		conf.ThConf.General.LogFile,
		log.LevelMap[conf.ThConf.General.LogLevel])

	log.SetLogger(OUTPUT_DRV, log_args)
	log.SetLogFuncCall(true)

}

func serve() {

	addr := conf.ThConf.Server.Host + ":" + conf.ThConf.Server.Port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error("Error when try to listen on %s: %s", addr, err.Error())
		return
	}
	defer ln.Close()

	log.Info("Thor serve on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("Accept: %s", err.Error())
			continue
		}
		go func(){
			mng := &manager.Manager{Conn:conn}
			err := mng.Thunder()
			if err != nil {
				log.Error("Thunder Wrong!: %s", err.Error())
				return
			}
		}()
	}
}

func main() {

	serve()
}