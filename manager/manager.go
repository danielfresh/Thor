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

package manager

import (
	"net"
	"errors"
	"time"
	"sync"
	"io"
	"strings"
	"fmt"

	ad "thor/adaptor"
	"thor/log"
	"thor/config"
)

type InitFunc func(map[string]string) (Deal, error)

var (
	deals = make(map[string]map[string]InitFunc)
)

func RegisterDeal(ctg string, name string, dealInit InitFunc) error {

	if deal_ctg, ok := deals[ctg]; !ok {
		deals[ctg] = make(map[string]InitFunc)
		deals[ctg][name] = dealInit
		log.Info("Regist deal: %s %s", ctg, name)

	} else {
		if deal_ctg == nil {
			deals[ctg] = make(map[string]InitFunc)
		}

		if deal_obj, ok := deal_ctg[name]; ok {
			log.Warn("Already exists: %s %s", ctg, name)
			return nil
		} else {
			if deal_obj == nil {
				deals[ctg][name] = dealInit
				log.Info("Regist deal: %s %s", ctg, name)
			}
		}
	}

	return nil
}

func GetDeal(ctg string, name string, options map[string]string) (Deal, error) {

	if deal_ctg, ok := deals[ctg]; ok {
		if deal_init, ok := deal_ctg[name]; ok {
			return deal_init(options)
		}
	}

	return nil, errors.New("when init, found no deal object")
}

type Manager struct {

	dealType   string
	dealName   string
	// Options of Deal
	dealData   map[string]string

	// Deal result
	dealResult map[string][]map[string]string

	interval   time.Duration
	executions int

	mu         sync.Mutex
	// Deal ends
	end        bool
	// RecvRequest -> RunDeal -> SendResponse
	firstRun   chan bool
	Conn       net.Conn
}

func (dm *Manager)Thunder() error {

	{
		// Init
		dm.end = true
		dm.firstRun = make(chan bool)
	}

	// Recv & Parse Request
	dm.RecvRequest()

	// Waiting for parsing request
	select {
	case <-time.After(5 * time.Second):
		return errors.New("Thunder: timeout when parsing request")
	case <-dm.firstRun:
	}

	dm.mu.Lock()

	// Get Deal
	deal, err := GetDeal(dm.dealType, dm.dealName, dm.dealData)
	if err != nil {
		return fmt.Errorf("Error when init deal %s %s: %s", dm.dealType, dm.dealName, err.Error())
	}
	if deal == nil {
		return errors.New("Found no deal")
	}

	// Do Deal Asynchronously
	dm.RunDeal(deal)

	dm.mu.Unlock()

	// Send Result Asynchronously
	dm.SendResult()

	return nil
}

func (dm *Manager)Stop() {
	log.Info("Try to stop all job.")
	dm.end = false
	dm.Conn.Close()
}

func (dm *Manager)RunDeal(deal Deal) error {

	runFirst := false
	exectimes := 0

	go func() {
		limit := time.Tick(dm.interval)
		for {

			if !dm.end {
				log.Info("RunDeal End")
				return
			}
			start := time.Now()
			result, err := deal.Run()
			end := time.Now()
			log.Debug("RunDeal use %s", end.Sub(start).String())

			if err != nil {
				log.Error("RunDeal error: %s", err.Error())
				result["Succ"] = []map[string]string{map[string]string{"success": "false"}}
				dm.dealResult = result
			} else {
				result["Succ"] = []map[string]string{map[string]string{"success": "true"}}
			}

			dm.dealResult = result
			log.Debug("RunDeal result: %+v", dm.dealResult)

			if !runFirst {
				runFirst = true
				dm.firstRun <- true
			}

			exectimes += 1
			if dm.executions != 0 && exectimes >= dm.executions {
				return
			}

			<-limit
		}
	}()

	return nil
}

// Support two types of requests currently:
// 1. Executor/Collector request
// 2. End request
func (dm *Manager)RecvRequest() {

	go func() {

		firstRecv := true

		defer func() {
			dm.Stop()
		}()

		for {
			if !dm.end {
				log.Info("RecvRequest End")
				return
			}

			// recv request
			// dm.Conn.SetReadDeadline(time.Now().Add(time.Second * 2))
			var buffer = make([]byte, 65536)
			n, err := dm.Conn.Read(buffer)
			if err != nil {
				// Closed connection
				if err == io.EOF {
					log.Error("RecvRequest got EOF when read.")
					dm.Stop()
					return
				}
				log.Error("RecvRequest got error: %s", err.Error())
				continue
			}

			// parse repuest
			req, err := ad.ParseRequest(buffer, n)
			if err != nil || req == nil {
				log.Error("RecvRequest error when parses request: %s", err.Error())
				continue
			}

			if ad.Auth(req.Token, req.HeaderTime) != true {
				dm.Stop()
				log.Info("RecvRequest auth failed: token %s time %s", req.Token, req.HeaderTime)
				return
			}

			// end
			if req.Type == "end" {
				log.Info("RecvRequest got END.")
				dm.Stop()
				continue
			}

			dm.mu.Lock()

			dm.dealType = req.Type
			dm.dealData = req.Content
			dm.interval = req.Interval.Duration
			if req.Name == "" {
				if dm.dealType == "collector" {
					dm.dealName = config.ThConf.Deal.Collector
				} else {
					dm.dealName = config.ThConf.Deal.Executor
				}
			} else {
				dm.dealName = req.Name
			}
			dm.executions = req.Executions
			log.Info("RecvRequest request type %s data %s interval %s executions %d",
				dm.dealType, dm.dealData, dm.interval.String(), dm.executions)
			dm.mu.Unlock()

			if firstRecv {
				firstRecv = false
				dm.firstRun <- true
			}
		}
	}()

	return
}

func (dm *Manager)SendResult() error {

	<-dm.firstRun

	exectimes := 0

	limit := time.Tick(dm.interval)
	for {

		if !dm.end {
			log.Info("SendResult End")
			return nil
		}

		if dm.dealResult == nil {
			continue
		}

		dm.Conn.SetWriteDeadline(time.Now().Add(time.Second * 2))
		meters, err := ad.PackResponse(dm.dealResult)
		if err != nil {
			log.Error("SendResult error when pack response: %s", err.Error())
			continue
		}
		n, err := dm.Conn.Write([]byte(meters))
		if err != nil {
			log.Error("SendResult error when write: %s", err.Error())
			errstr := err.Error()
			// Closed connection
			if strings.Contains(errstr, "use of closed network connection") {
				log.Error("SendResult got error: use of closed network connection")
				dm.Stop()
				return nil
			}

			continue
		}

		if n != len(meters) {
			log.Error("Send less, send %d, except %d", n, len(dm.dealResult))
		}

		log.Debug("SendResult send: %s", string(meters))

		exectimes += 1
		if dm.executions != 0 && exectimes >= dm.executions {
			return nil
		}

		<-limit
	}

	return nil
}



