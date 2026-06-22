// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"context"
	"crypto/tls"
	"log"
	"syscall"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"

	"nethsm/internal/hw"
	"nethsm/internal/localconf"
	"nethsm/internal/util"
)

const (
	defaultNTPInterval = 64 * time.Second
	kodNTPInterval     = time.Hour
)

var timeInizializedNtfy, TimeInitializedSig = util.MakeNtfyPair()

type timeConf struct {
	ntpIP   string
	ntsName string
}

func timeConfOf(c *localconf.LocalConf) timeConf {
	if c == nil {
		return timeConf{}
	}
	return timeConf{ntpIP: derefStr(c.NtpIP), ntsName: derefStr(c.NtsName)}
}

func derefStr(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

type timeTask struct {
	configCh  chan localconf.ChangeReq
	lastConf  timeConf
	cancelNTP context.CancelFunc
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
	rtc, _ := rtcAndNow()
	t := rtc.Add(time.Duration(offsetS) * time.Second)
	err := setSystemTime(t)
	log.Printf("Setting system time to %v", t)
	if err != nil {
		log.Printf("Failed to set system time: %v", err)
	}
}

// setTimeAndUpdateOffset adjusts the system clock by clockOffset relative to
// the current time and persists the resulting RTC offset so it survives the
// next boot.
func setTimeAndUpdateOffset(clockOffset time.Duration) error {
	rtc, now := rtcAndNow()
	newTime := now.Add(clockOffset)
	if err := setSystemTime(newTime); err != nil {
		if hw.IsTesting() {
			log.Printf("Ignoring setSystemTime err in testing: %v", err)
		} else {
			return err
		}
	}
	log.Printf("Set system time to %v (clock offset %v)", newTime.Round(0), clockOffset)
	offsetS := int(newTime.Sub(rtc).Seconds())
	if err := localconf.UpdateTimeOffset(offsetS); err != nil {
		log.Printf("Failed to update time offset: %v", err)
	}
	return nil
}

// syncTime queries the NTP or NTS server and adjusts the system clock.
// Returns the server's suggested poll interval (at least defaultNTPInterval).
func syncTime(ntpIP, ntsName string) (time.Duration, error) {
	var resp *ntp.Response
	var err error

	if ntsName != "" {
		// NTS mode: use ntpIP as server address, ntsName for TLS SNI.
		var session *nts.Session
		session, err = nts.NewSessionWithOptions(ntpIP, &nts.SessionOptions{
			TLSConfig: &tls.Config{ServerName: ntsName},
		})
		if err == nil {
			resp, err = session.Query()
		}
	} else {
		resp, err = ntp.Query(ntpIP)
	}

	if err != nil {
		return 0, err
	}

	if resp.IsKissOfDeath() {
		return 0, ntp.ErrKissOfDeath
	}

	if setErr := setTimeAndUpdateOffset(resp.ClockOffset); setErr != nil {
		return 0, setErr
	}

	if resp.Poll > defaultNTPInterval {
		return resp.Poll, nil
	}
	return defaultNTPInterval, nil
}

// startNTP stops any running NTP loop and starts a new background loop that
// syncs immediately on its first iteration. Blocks until that first sync
// completes and returns its error; the loop continues running regardless.
func (t *timeTask) startNTP(ntpIP, ntsName string) error {
	if t.cancelNTP != nil {
		t.cancelNTP()
		t.cancelNTP = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancelNTP = cancel
	firstErr := make(chan error)
	go func(firstErr chan<- error) {
		interval := defaultNTPInterval
		for {
			pollInterval, err := syncTime(ntpIP, ntsName)
			if err != nil {
				log.Printf("NTP sync failed: %v", err)
			}
			if firstErr != nil {
				firstErr <- err
				firstErr = nil
			}
			switch err {
			case ntp.ErrKissOfDeath:
				interval = kodNTPInterval
			case nil:
				interval = pollInterval
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
		}
	}(firstErr)
	return <-firstErr
}

func (t *timeTask) Run() {
	conf := localconf.Get()
	if conf.TimeOffsetS != nil {
		log.Printf("Initialize system time with offset %v from local config cache", *conf.TimeOffsetS)
		applyTimeOffset(*conf.TimeOffsetS)
	}
	t.lastConf = timeConfOf(&conf)

	if derefStr(conf.NtpIP) != "" {
		if err := t.startNTP(derefStr(conf.NtpIP), derefStr(conf.NtsName)); err != nil {
			log.Printf("Initial NTP sync failed: %v", err)
		}
	}

	timeInizializedNtfy()

	for req := range t.configCh {
		var err error
		full := localconf.Get()

		// Handle NTP config change.
		newConf := timeConfOf(&full)
		if newConf != t.lastConf {
			t.lastConf = newConf
			if newConf.ntpIP != "" {
				if syncErr := t.startNTP(newConf.ntpIP, newConf.ntsName); syncErr != nil {
					log.Printf("NTP sync after config change failed: %v", syncErr)
					err = syncErr
				}
			} else if t.cancelNTP != nil {
				t.cancelNTP()
				t.cancelNTP = nil
			}
		}

		req.Reply <- err
	}
}

func setSystemTime(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	return syscall.Settimeofday(&tv)
}

// rtcAndNow returns a pair of the current RTC and system time. It does
// that by tracking the wall clock from before any corrections were applied
// (t0).
var rtcAndNow = func() func() (time.Time, time.Time) {
	t0 := time.Now() // RTC wall-time at boot, before any corrections
	return func() (time.Time, time.Time) {
		now := time.Now()
		return t0.Round(0).Add(now.Sub(t0)), now
	}
}()
