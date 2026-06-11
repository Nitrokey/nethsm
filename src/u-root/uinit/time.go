// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"log"
	"syscall"
	"time"

	"nethsm/internal/localconf"
)

type timeConf struct {
	timeOffsetS int
}

func timeConfOf(c *localconf.LocalConf) timeConf {
	if c == nil {
		return timeConf{}
	}
	return timeConf{timeOffsetS: c.TimeOffsetS}
}

type timeTask struct {
	configCh chan localconf.ChangeReq
	lastConf timeConf
}

func NewTimeTask() *timeTask {
	t := &timeTask{
		configCh: make(chan localconf.ChangeReq, 1),
	}
	localconf.RegisterConsumer(t.configCh)
	return t
}

func applyTimeOffset(offsetS int) {
	if offsetS == 0 {
		return
	}
	t := rtcTime().Add(time.Duration(offsetS) * time.Second)
	log.Printf("Setting local time to %v", t)
	if err := setSystemTime(t); err != nil {
		log.Printf("Failed to set system time: %v", err)
	}
}

func (t *timeTask) Run() {
	conf := localconf.Get()
	t.lastConf = timeConfOf(&conf)
	applyTimeOffset(t.lastConf.timeOffsetS)

	for req := range t.configCh {
		newConf := timeConfOf(req.Conf)
		if newConf != t.lastConf {
			t.lastConf = newConf
			applyTimeOffset(newConf.timeOffsetS)
		}
		req.Reply <- nil
	}
}

func setSystemTime(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	return syscall.Settimeofday(&tv)
}

var rtcTime = func() func() time.Time {
	t0 := time.Now() // stores RTC wall-time at t0
	return func() time.Time {
		return t0.Round(0).Add(time.Since(t0))
	}
}()
