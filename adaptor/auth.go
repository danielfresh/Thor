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

package adaptor

import (
	"strings"
	"crypto/md5"
	"encoding/hex"

	"thor/config"
	"thor/util"
	"thor/log"
)

func Auth(token string, headertime string) bool {

	key := config.ThConf.Auth.AuthKey

	ips, err := util.GetLocalAddrs()
	if err != nil {
		log.Error("Error when get local addrs: %s", err.Error())
		return false
	}

	for _, ip := range ips {
		authstr := headertime + "|" + key + "|" + ip
		restr := util.Reverse(authstr)

		md5Ctx := md5.New()
		md5Ctx.Write([]byte(restr))
		cipherStr := md5Ctx.Sum(nil)

		if strings.ToLower(token) == strings.ToLower(hex.EncodeToString(cipherStr)) {
			return true
		}
	}

	return false
}
