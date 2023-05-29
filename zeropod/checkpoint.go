package zeropod

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/pkg/process"
	"github.com/containerd/containerd/runtime/v2/runc"
	runcC "github.com/containerd/go-runc"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func (c *Container) scaleDown(ctx context.Context, container *runc.Container, p process.Process) error {
	if c.cfg.Stateful {
		if err := c.checkpoint(ctx, container, p); err != nil {
			return err
		}
	} else {
		log.G(ctx).Infof("container is not stateful, scaling down by killing")

		c.scaledDown = true
		if err := p.Kill(ctx, 9, false); err != nil {
			return err
		}
	}

	beforeActivator := time.Now()
	if err := c.startActivator(ctx, container); err != nil {
		log.G(ctx).Errorf("unable to start zeropod: %s", err)
		return err
	}

	if !c.cfg.Stateful {
		log.G(ctx).Infof("activator started in %s", time.Since(beforeActivator))
		return nil
	} else {
		// after checkpointing criu locks the network until the process is
		// restored by inserting some nftables rules. As we start our activator
		// instead of restoring the process right away, we remove these
		// rules. https://criu.org/CLI/opt/--network-lock
		if err := unlockNetwork(c.netNS, p.Pid()); err != nil {
			log.G(ctx).Errorf("unable to remove nftable: %s", err)
			return err
		}

		log.G(ctx).Infof("activator started and net-lock removed in %s", time.Since(beforeActivator))
	}

	return nil
}

func (c *Container) checkpoint(ctx context.Context, container *runc.Container, p process.Process) error {
	snapshotDir := snapshotDir(container.Bundle)

	if err := os.RemoveAll(snapshotDir); err != nil {
		return fmt.Errorf("unable to prepare snapshot dir: %w", err)
	}

	workDir := path.Join(snapshotDir, "work")
	log.G(ctx).Infof("checkpointing process %d of container to %s", p.Pid(), snapshotDir)

	initProcess, ok := p.(*process.Init)
	if !ok {
		return fmt.Errorf("process is not of type %T, got %T", process.Init{}, p)
	}

	opts := &runcC.CheckpointOpts{
		WorkDir:                  workDir,
		AllowOpenTCP:             true,
		AllowExternalUnixSockets: true,
		AllowTerminal:            false,
		FileLocks:                false,
		EmptyNamespaces:          []string{},
	}

	if c.cfg.PreDump {
		// for the pre-dump we set the ImagePath to be a sub-path of our container image path
		opts.ImagePath = preDumpDir(container.Bundle)

		beforePreDump := time.Now()
		if err := initProcess.Runtime().Checkpoint(ctx, container.ID, opts, runcC.PreDump); err != nil {
			c.scaledDown = false

			log.G(ctx).Errorf("error pre-dumping container: %s", err)
			b, err := os.ReadFile(path.Join(workDir, "dump.log"))
			if err != nil {
				log.G(ctx).Errorf("error reading dump.log: %s", err)
			}
			log.G(ctx).Errorf("dump.log: %s", b)
			return err
		}

		log.G(ctx).Infof("pre-dumping done in %s", time.Since(beforePreDump))
	}

	// not sure what is causing this but without adding these nftables
	// rules here already, connections during scaling down sometimes
	// timeout, even though criu should add these rules before
	// checkpointing.
	if err := lockNetwork(c.netNS); err != nil {
		return err
	}

	// TODO: as a result of the IP tables rules we sometimes get > 1s delays
	// when the client is connecting during checkpointing. This can be
	// reproduced easily by running the benchmark without any sleeps. This is
	// most probably caused by TCP SYN retransmissions:
	// $ netstat -s | grep -i retrans
	// 3 segments retransmitted
	// TCPSynRetrans: 3
	// Not sure if we can even do something about this as the issue is on the
	// client side.
	// https://arthurchiao.art/blog/customize-tcp-initial-rto-with-bpf/#tl-dr

	c.scaledDown = true

	if c.cfg.PreDump {
		// ParentPath is the relative path from the ImagePath to the pre-dump dir.
		opts.ParentPath = relativePreDumpDir()
	}

	// ImagePath is always the same, regardless of pre-dump
	opts.ImagePath = containerDir(container.Bundle)

	beforeCheckpoint := time.Now()
	if err := initProcess.Runtime().Checkpoint(ctx, container.ID, opts); err != nil {
		c.scaledDown = false

		log.G(ctx).Errorf("error checkpointing container: %s", err)
		b, err := os.ReadFile(path.Join(workDir, "dump.log"))
		if err != nil {
			log.G(ctx).Errorf("error reading dump.log: %s", err)
		}
		log.G(ctx).Errorf("dump.log: %s", b)
		return err
	}

	log.G(ctx).Infof("checkpointing done in %s", time.Since(beforeCheckpoint))

	return nil
}

func lockNetwork(netNS ns.NetNS) error {
	nft, err := nftables.New(nftables.WithNetNSFd(int(netNS.Fd())))
	if err != nil {
		return err
	}
	defer nft.CloseLasting()

	table := &nftables.Table{Name: "zeropod", Family: nftables.TableFamilyINet}

	nft.AddTable(table)
	chain := &nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	}

	nft.AddChain(chain)

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}

	nft.AddRule(rule)

	return nft.Flush()
}

func unlockNetwork(netNS ns.NetNS, pid int) error {
	nft, err := nftables.New(nftables.WithNetNSFd(int(netNS.Fd())))
	if err != nil {
		return err
	}
	defer nft.CloseLasting()

	if pid != 0 {
		nft.DelTable(&nftables.Table{Name: "CRIU-" + strconv.Itoa(pid), Family: nftables.TableFamilyINet})
	}

	nft.DelTable(&nftables.Table{Name: "zeropod", Family: nftables.TableFamilyINet})

	return nft.Flush()
}
