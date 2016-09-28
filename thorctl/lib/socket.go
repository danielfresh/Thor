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

package lib

import (
	"encoding/json"
	"fmt"
	"thorctl/util"
	"crypto/md5"
	"encoding/hex"
	"net"
	"time"
	"io"
)

const (
	KEY = "0FE3BE1EF6204C678C5F4B81D7D8564C"
)

func SendRequest(conn net.Conn, cmdtype string, host string, interval string, count int, content map[string]string) error {

	// md5 hash
	authstr := "a" + "|" + KEY + "|" + host
	restr := util.Reverse(authstr)
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(restr))
	cipherStr := md5Ctx.Sum(nil)
	token := hex.EncodeToString(cipherStr)


	req := &Request{
		Token: token,
		HeaderTime: "a",
		Type: cmdtype,
		Interval: interval,
		Executions: count,
		Content: content,
	}

	reqstr, err := json.Marshal(req)
	if err != nil {
		fmt.Println("Error when Marshal", err)
		return err
	}

	_, err = conn.Write(reqstr)
	if err != nil {
		fmt.Println("Error when Write", err)
		return err
	}

	// fmt.Println("Send request to thor:", string(reqstr))

	return nil
}

func RecvResponse(conn net.Conn, count int, interval string, display func(data []byte) error) {

	defer conn.Close()

	c := 0
	for {
		var buf = make([]byte, 65535)
		du, err := time.ParseDuration(interval)
		if err != nil {
			fmt.Println("Timeout when RecvResponse:", err.Error())
			return
		}
		conn.SetReadDeadline(time.Now().Add(du * 2 + 10 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {

			if err == io.EOF {
				fmt.Println("EOF")
				return
			}

			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				fmt.Println("Timeout when RecvResponse:", err.Error())
				return
			}

			fmt.Println("Error when RecvResponse:", err.Error())
			continue
		}

		display(buf[:n])

		c += 1
		if count != 0 && c >= count {
			return
		}
	}
}
