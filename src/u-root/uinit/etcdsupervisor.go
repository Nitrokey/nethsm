// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bufio"
	"container/ring"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"nethsm/internal/localconf"
	. "nethsm/internal/util"
)

type EtcdMode = int

const (
	/* if /etcd/data empty (on first boot)
	  create new 1-node cluster ready to accept new members
	    - cannot fail

	if /etcd/data exists (after first boot)
	  use existing cluster and try to connect to existing members if
	  any were added in the past
	    - cannot fail if new members were never added
	  - !! will fail if cluster quorum is not met anymore i.e. if the
	    majority of other members is unreachable (either they are down or we
	    are isolated ourselves)
	*/
	EtcdNormal EtcdMode = iota

	/* !! will delete /etcd/data !!
	   create a new node as member of an existing cluster,
	   assuming the cluster has already added our peer-urls

	   !! will fail for any of the following is true
	   - the wrong configuration is passed
	   - the configured peers are not reachable
	   - the cluster has not previously added this member
	*/
	EtcdClusterJoin
)

var etcdModeName = map[EtcdMode]string{
	EtcdNormal:      "normal",
	EtcdClusterJoin: "cluster join",
}

type JoinArgs struct {
	InitialCluster string // of the form "name1=url1:2380,name2=url2:2380,..."
}

const (
	etcdBackupJoin     = "/data/etcd.backup"
	etcdBackupSnapshot = "/data/etcd.backup.snapshot"
)

type etcdConf struct {
	tlsCert, tlsKey, tlsCA, deviceID string
}

func etcdConfOf(c *localconf.LocalConf) etcdConf {
	if c == nil {
		return etcdConf{}
	}
	return etcdConf{
		tlsCert:  c.TLSCert,
		tlsKey:   c.TLSKey,
		tlsCA:    c.TLSTrustedCA,
		deviceID: c.DeviceID,
	}
}

type EtcdCmdKind int

const (
	EtcdCmdJoin EtcdCmdKind = iota
	EtcdCmdForceNew
)

type EtcdCommand struct {
	Kind     EtcdCmdKind
	JoinArgs JoinArgs
	Reply    chan<- error
}

type etcdSupervisor struct {
	SendCmd  func(EtcdCommand)
	Shutdown func()
	// internal
	configRcv <-chan localconf.ChangeReq
	cmdsRcv   <-chan EtcdCommand
	stopSig   <-chan struct{}
	// stopEtcd reflects the currently running etcd process.
	// Accessible for tests to inject mock processes.
	stopEtcd func() // blocks until process exited
	// lastConf is the config used for the most recent successful start.
	lastConf etcdConf
}

func NewEtcdSupervisor() *etcdSupervisor {
	configCh := make(chan localconf.ChangeReq)
	cmdCh := make(chan EtcdCommand)
	stopNtfy, stopSig := MakeNtfyPair()
	s := &etcdSupervisor{
		configRcv: configCh,
		cmdsRcv:   cmdCh,
		SendCmd: func(c EtcdCommand) {
			cmdCh <- c
		},
		stopSig:  stopSig,
		Shutdown: stopNtfy,
	}
	localconf.RegisterConsumer(configCh)
	return s
}

func (s *etcdSupervisor) Run() {
	const maxRetries = 5
	conf := localconf.Get()
	var err error
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			log.Printf("etcd: retrying start in 5 seconds (attempt %d/%d)", i, maxRetries)
			time.Sleep(5 * time.Second)
		}
		err = s.launch(EtcdNormal, etcdConfOf(&conf))
		if err == nil {
			break
		}
		log.Printf("etcd: failed to start: %v", err)
	}
	if err != nil {
		log.Printf("etcd: giving up after %d retries", maxRetries)
		return
	}

	for {
		select {
		case <-s.stopSig:
			s.stopEtcd()
			return

		case req := <-s.configRcv:
			newConf := etcdConfOf(req.Conf)
			if newConf == s.lastConf {
				req.Reply <- nil
				continue
			}
			s.stopEtcd()
			if err := s.launch(EtcdNormal, newConf); err != nil {
				log.Printf("etcd: config update failed (%v), reverting to previous config", err)
				if restartErr := s.launch(EtcdNormal, s.lastConf); restartErr != nil {
					req.Reply <- fmt.Errorf("config update failed (%w) and rollback failed: %w", err, restartErr)
				} else {
					req.Reply <- err
				}
			} else {
				req.Reply <- nil
			}

		case cmd := <-s.cmdsRcv:
			s.stopEtcd()
			switch cmd.Kind {
			case EtcdCmdJoin:
				err := s.launch(EtcdClusterJoin, s.lastConf, cmd.JoinArgs)
				if err != nil {
					cmd.Reply <- err
				} else {
					// give the new member time to learn from the cluster
					time.Sleep(10 * time.Second)
					cmd.Reply <- nil
				}
			case EtcdCmdForceNew:
				err := restoreFromSnapshotEtcd(s.lastConf)
				cmd.Reply <- err
				// reboot is imminent; wait for shutdown signal rather than
				// re-entering the select and accidentally restarting etcd
				<-s.stopSig
				return
			default:
				cmd.Reply <- fmt.Errorf("unknown etcd command %d", cmd.Kind)
			}
		}
	}
}

// launch starts etcd in the given mode. If a cluster join fails immediately,
// it restores the backup and falls back to EtcdNormal, returning the original
// join error so the caller can report it.
func (s *etcdSupervisor) launch(mode EtcdMode, conf etcdConf, joinArgs ...JoinArgs) error {
	err := s.startAndWait(mode, conf, joinArgs...)
	if err != nil && mode == EtcdClusterJoin {
		log.Printf("etcd: join failed (%v), restoring backup", err)
		if restoreErr := restoreJoinBackup(); restoreErr != nil {
			return fmt.Errorf("join failed (%w) and restore failed: %w", err, restoreErr)
		}
		if normalErr := s.startAndWait(EtcdNormal, conf); normalErr != nil {
			return fmt.Errorf("join failed (%w) and normal restart failed: %w", err, normalErr)
		}
		return err // report the join error even though etcd is now running normally
	}
	return err
}

// startAndWait launches etcd, waits for it to become ready (or fail/timeout),
// and returns. On success s.kill and s.etcdExited are updated to reflect the new
// process; s.lastConf is updated to conf.
func (s *etcdSupervisor) startAndWait(mode EtcdMode, conf etcdConf, joinArgs ...JoinArgs) error {
	G.s.ClearErr()
	G.s.Logf("Starting etcd in %s mode", etcdModeName[mode])

	if mode == EtcdClusterJoin {
		if len(joinArgs) == 0 || strings.TrimSpace(joinArgs[0].InitialCluster) == "" {
			return fmt.Errorf("EtcdClusterJoin requires a non-empty InitialCluster")
		}
		if err := backupEtcd(etcdBackupJoin); err != nil {
			return err
		}
	}

	cmd := buildEtcdCmd(mode, conf, joinArgs...)

	exitedNtfy, exitedSig := MakeNtfyPair()
	aliveNtfy, aliveSig := MakeNtfyPair()

	G.s.Logf("launching: %s", cmd)
	cancel, logPipe := G.s.CancelableBackgroundExecAsf(exitedNtfy, &G.etcdProcessState, G.etcdUIDGID, "%s", cmd)
	if err := G.s.Err(); err != nil {
		return fmt.Errorf("couldn't exec etcd: %w", err)
	}

	s.stopEtcd = func() {
		cancel()
		<-exitedSig
	}
	lastEtcdError := "unknown error"
	G.etcdLogs = ring.New(1024)

	var logsDone sync.WaitGroup
	logsDone.Add(1)
	go func() {
		defer logsDone.Done()
		readEtcdLogs(logPipe, aliveNtfy, &lastEtcdError)
	}()

	select {
	case <-exitedSig:
		logsDone.Wait()
		log.Printf("etcd: exited immediately: %s", lastEtcdError)
		return fmt.Errorf("etcd exited immediately: %s", lastEtcdError)

	case <-aliveSig:
		log.Printf("etcd: ready")
		if mode == EtcdClusterJoin {
			log.Printf("etcd: join succeeded, removing backup")
			if err := os.RemoveAll(etcdBackupJoin); err != nil {
				return err
			}
		}
		if mode == EtcdNormal {
			if err := os.RemoveAll(etcdBackupSnapshot); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		s.lastConf = conf
		return G.s.Err()

	case <-time.After(30 * time.Second):
		cancel()
		<-exitedSig
		logsDone.Wait()
		log.Printf("etcd: startup timed out: %s", lastEtcdError)
		return fmt.Errorf("etcd took too long to start: %s", lastEtcdError)
	}
}

// buildEtcdCmd constructs the etcd command string for the given mode and
// config. As a side effect it writes TLS credentials to /tmp if configured.
func buildEtcdCmd(mode EtcdMode, conf etcdConf, joinArgs ...JoinArgs) string {
	cmd := "/bin/etcd" +
		" --listen-client-urls=http://169.254.169.2:2379" +
		" --listen-client-http-urls=http://127.0.0.1:2382" + // disables HTTP on client port
		" --advertise-client-urls=" +
		" --data-dir=/data/etcd" +
		" --peer-skip-client-san-verification=true" +
		" --auto-compaction-retention=1h" +
		" --quota-backend-bytes=5694816256" + // should not be more than RAM
		" --max-txn-ops=512"

	if mode == EtcdClusterJoin && len(joinArgs) > 0 {
		cmd += " --initial-cluster-state=existing"
		cmd += " --initial-cluster=" + strings.TrimSpace(joinArgs[0].InitialCluster)
	} else {
		cmd += " --initial-cluster-state=new"
	}

	name := "nethsm"
	if conf.tlsCert != "" && conf.tlsKey != "" && conf.tlsCA != "" {
		G.s.Logf("Starting etcd with TLS")
		fn := "/tmp/etcd_tls_cert.pem"
		os.WriteFile(fn, []byte(conf.tlsCert), 0o666)
		cmd += " --peer-cert-file=" + fn
		fn = "/tmp/etcd_tls_key.pem"
		os.WriteFile(fn, []byte(conf.tlsKey), 0o666)
		cmd += " --peer-key-file=" + fn
		fn = "/tmp/etcd_tls_trusted_ca.pem"
		os.WriteFile(fn, []byte(conf.tlsCA), 0o666)
		cmd += " --peer-trusted-ca-file=" + fn
		cmd += " --peer-client-cert-auth=true"
		cmd += " --listen-peer-urls=https://169.254.200.2:2380,https://[fc00:1:200::2]:2380"
		if conf.deviceID != "" {
			name = conf.deviceID
		}
	}

	cmd += " --name=" + name
	return cmd
}

// readEtcdLogs reads etcd's log output, fires aliveNtfy when etcd is ready,
// and stores warn/error entries in the G.etcdLogs ring buffer.
func readEtcdLogs(logPipe io.ReadCloser, aliveNtfy func(), lastEtcdError *string) {
	logs := bufio.NewReader(logPipe)
	for {
		line, err := logs.ReadString('\n')
		if err != nil {
			return
		}
		log.Printf("etcd: %s", line)
		if strings.Contains(line, "ready to serve client requests") {
			aliveNtfy()
		}
		if strings.Contains(line, "fatal") || strings.Contains(line, "error") {
			*lastEtcdError = line
		}
		var logItem clusterLogItem
		if err := json.Unmarshal([]byte(line), &logItem); err == nil && logItem != nil {
			if level, ok := logItem["level"].(string); ok {
				switch strings.ToLower(level) {
				case "debug", "info":
					// skip
				default:
					G.etcdLogs.Value = logItem
					G.etcdLogs = G.etcdLogs.Next()
				}
			}
		}
	}
}

func backupEtcd(dest string) error {
	G.s.Logf("Moving previous etcd data to %s", dest)
	if err := os.Rename("/data/etcd", dest); err != nil {
		return err
	}
	if err := os.Mkdir("/data/etcd", 0o700); err != nil {
		return err
	}
	if err := os.Chown("/data/etcd", G.etcdUIDGID, G.etcdUIDGID); err != nil {
		return err
	}
	return nil
}

func restoreJoinBackup() error {
	if err := os.RemoveAll("/data/etcd"); err != nil {
		return err
	}
	return os.Rename(etcdBackupJoin, "/data/etcd")
}

func restoreFromSnapshotEtcd(conf etcdConf) error {
	if err := backupEtcd(etcdBackupSnapshot); err != nil {
		return err
	}

	G.s.ClearErr()
	name := "nethsm"
	if conf.deviceID != "" {
		name = conf.deviceID
	}
	G.s.ExecAsf(G.etcdUIDGID, "/bin/etcdutl snapshot restore %s/member/snap/db --bump-revision 1 --mark-compacted --skip-hash-check=true --data-dir /data/etcd --name %s --initial-cluster %s=https://127.0.0.1:2380 --initial-cluster-token etcd-%s-recovered --initial-advertise-peer-urls https://127.0.0.1:2380", etcdBackupSnapshot, name, name, name)
	if origErr := G.s.Err(); origErr != nil {
		log.Printf("restoreFromSnapshotEtcd: restore failed, restoring internal backup")
		if err := os.RemoveAll("/data/etcd"); err != nil {
			return fmt.Errorf("snapshot restore (%w) AND removeall failed: %w", origErr, err)
		}
		if err := os.Rename(etcdBackupSnapshot, "/data/etcd"); err != nil {
			return fmt.Errorf("snapshot restore (%w) AND backup rename failed: %w", origErr, err)
		}
		return origErr
	}
	return nil
}
