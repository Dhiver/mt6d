package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/logger"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	// RuleHandleNum maintains a global counter in order to identify the next rule handle number that will be assigned to the next rule
	// Each time that a rule is inserted, this variable must be incremented
	// Yes, this can be improved, but the package github.com/google/nftables needs to be improved for that (we should be able to get the rule handle after insertion)
	RuleHandleNum = uint64(3)
)

type nftMt6d struct {
	conn        *nftables.Conn
	table       *nftables.Table
	inputChain  *nftables.Chain
	outputChain *nftables.Chain
}

func newNftMt6d(nftc *nftables.Conn) (*nftMt6d, error) {
	table := nftc.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "mt6d",
	})
	inChain := nftc.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookInput,
		Type:     nftables.ChainTypeFilter,
	})
	outChain := nftc.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookOutput,
		Type:     nftables.ChainTypeFilter,
	})
	return &nftMt6d{
		conn:        nftc,
		table:       table,
		inputChain:  inChain,
		outputChain: outChain,
	}, nftc.Flush()
}

func (n *nftMt6d) insertIcmpv6Rule(qn uint16) error {
	// ICMPv6 traffic is moved in netfilter queue n°1
	// nft --debug all insert rule ip6 mt6d input ip6 nexthdr ipv6-icmp counter queue num 1
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: n.inputChain,
		Exprs: []expr.Any{
			// payload load 1b @ network header + 6 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       6,
				Len:          1,
			},
			// cmp eq reg 1 0x0000003a
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_ICMPV6},
			},
			// counter pkts 0 bytes 0
			&expr.Counter{
				Packets: 0,
				Bytes:   0,
			},
			// queue num 1
			&expr.Queue{
				Num: 1,
			},
		},
	})
	err := n.conn.Flush()
	if err == nil {
		RuleHandleNum++
	}
	return err
}

func (n *nftMt6d) delete() error {
	n.conn.DelTable(n.table)
	return n.conn.Flush()
}

func (n *nftMt6d) redirectToQ(srcIP, dstIP net.IP, qn uint16, nftChain *nftables.Chain) error {
	// Add nftables rule that redirects all traffic from the local host's true address to the remote host's true address into that stream's netfilter queue.
	// nft --debug all insert rule ip6 mt6d input ip6 saddr <stream source> ip6 daddr <stream destination> counter queue num <stream queue>
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: nftChain,
		Exprs: []expr.Any{
			// payload load 16b @ network header + 8 => reg 1
			&expr.Payload{
				Len:          16,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8,
				DestRegister: 1,
			},
			// cmp eq reg 1 0x000080fe 0x00000000 0x00000000 0x01000000
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     srcIP,
			},
			// payload load 16b @ network header + 24 => reg 1
			&expr.Payload{
				Len:          16,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       24,
				DestRegister: 1,
			},
			// cmp eq reg 1 0x000080fe 0x00000000 0x00000000 0x02000000
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     dstIP,
			},
			// counter pkts 0 bytes 0
			&expr.Counter{},
			// queue num x
			&expr.Queue{
				Num: qn,
			},
		},
	})
	err := n.conn.Flush()
	if err == nil {
		RuleHandleNum++
	}
	return err
}

func (n *nftMt6d) deleteRule(handle uint64, nfqChain *nftables.Chain) error {
	// nft --debug all delete rule ip6 mt6d input handle <handle>
	n.conn.DelRule(&nftables.Rule{
		Table: n.table,
		Chain: nfqChain,
	}, handle)

	return n.conn.Flush()
}

func computeSalt(rt int64, offset int64) int64 {
	now := time.Now().UTC().Unix()
	return ((now - (now % 10)) + (offset * rt)) / rt
}

func rehashRoutine(ctx context.Context, nftc *nftables.Conn, streams *Streams) {
	defer wg.Done()

	nft, err := newNftMt6d(nftc)
	if err != nil {
		logger.Fatalf("could not init mt6d nft: %s", err)
	}
	if err := nft.insertIcmpv6Rule(1); err != nil {
		logger.Fatalf("could not insert icmpv6 rule: %s", err)
	}

	// Get internal netlink interface
	intNetlk, err := netlink.LinkByName(config.GetString("internalnic"))
	if err != nil {
		logger.Fatalf("could not get netlink interface for link '%s': %s", config.GetString("internalnic"), err)
	}
	// Set interface up
	if err := netlink.LinkSetUp(intNetlk); err != nil {
		logger.Fatalf("could not set interface up: %s", err)
	}

	// Get external netlink interface
	extNetlk, err := netlink.LinkByName(config.GetString("externalnic"))
	if err != nil {
		logger.Fatalf("could not get netlink interface for link '%s': %s", config.GetString("externalnic"), err)
	}

	isInitialRun := true
	var offset int64
	rotationTime := config.GetInt64("rotationtime")
	for {

		salt := computeSalt(rotationTime, offset)
		offset++ // Hum... if two MT6D program don't start at the same time, they will generate different addresses ?
		fmt.Printf("Current salt is %d\n", salt)

		for sn, s := range *streams {
			if isInitialRun {
				if err := s.Init(intNetlk, nft); err != nil {
					logger.Fatalf("could not init stream %s: %s", sn, err)
				}
			} else {
				logger.Infof("I garbage collect old routes\n")
				if err := s.CleanOldRoutes(extNetlk, nft); err != nil {
					logger.Fatalf("could not clean old routes: %s", err)
				}
			}

			if err := s.Mutate(intNetlk, extNetlk, nft, salt, rotationTime); err != nil {
				logger.Fatalf("could not mutate profile: %s", err)
			}
		}

		if isInitialRun {
			isInitialRun = false
			continue
		}

		// Wait until rotation time has expired or context done
		select {
		case <-ctx.Done():
			logger.Infof("cleaning active routes...\n")
			for n, s := range *streams {
				if err := s.Flush(extNetlk, nft); err != nil {
					logger.Fatalf("could not flush all routes for stream %s: %s", n, err)
				}
			}
			logger.Infof("deleting nftables mt6d table...\n")
			if err := nft.delete(); err != nil {
				logger.Fatalf("could not delete mt6d table: %s\n", err)
			}
			logger.Infof("Exiting rehash routine\n")
			return
		case <-time.After(time.Duration(rotationTime) * time.Second):
		}
	}
}
