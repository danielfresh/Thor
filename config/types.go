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
	"time"
)

type ThorConf struct {
	General GeneralConf `toml:"general"`
	Server  ServerConf `toml:"server"`
	Deal    DealConf `toml:"deal"`
	Auth    AuthConf `toml:"auth"`
}

type (
	GeneralConf struct {
		LogLevel string `toml:"loglevel"`
		LogFile  string `toml:"logfile"`
		OverSold  bool `toml:"oversold"`
		OverSoldCpus string `toml:"soversold_cpus"`
	}

	ServerConf struct {
		Host string `toml:"host"`
		Port string `toml:"port"`
	}

	DealConf struct {
		Executions int `toml:"executions"`
		Interval   duration `toml:"interval"`
		Collector  string `toml:"collector"`
		Executor   string `toml:"executor"`
	}

	AuthConf struct {
		AuthKey string `toml:"authkey"`
	}

	duration struct {
		time.Duration
	}
)

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}