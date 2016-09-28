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

package config

import (
	"fmt"

	mconf "github.com/koding/multiconfig"
	"time"
)

var (
	DEFAULT_CONF = "/etc/thor/thor.toml"

	// init ThorConf with default config
	ThConf = &ThorConf{
		General: GeneralConf{
			LogLevel: "Info",
			LogFile: "/var/log/thor.log",
			OverSold: false,
			OverSoldCpus: ",42-63",
		},
		Server:  ServerConf{
			Host: "127.0.0.1",
			Port: "9898",
		},
		Deal:    DealConf{
			Executions: 0,
			Interval: duration{Duration: 2 * time.Second},
			Collector: "direct",
			Executor: "local",
		},
		Auth: AuthConf{
			AuthKey: "",
		},
	}
)

func LoadConfig(conf string) error {

	f := &mconf.FlagLoader{}
	e := &mconf.EnvironmentLoader{}
	t := &mconf.TOMLLoader{Path: DEFAULT_CONF}

	l := mconf.MultiLoader(e, t, f)
	err := l.Load(ThConf)
	if err != nil {
		return fmt.Errorf("Error when load config: %s", err.Error())
	}

	return nil
}