package main

import (
	"context"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/logger"
)

func icmpRoutine(ctx context.Context) {
	defer wg.Done()

	icmpNfq, err := netfilter.NewNFQueue(1, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		logger.Fatalf("could not get netfilter queue: %s", err)
	}
	//defer icmpNfq.Close() // Doesn't return....

	icmpPkts := icmpNfq.GetPackets()

	for {
		select {
		case <-ctx.Done():
			logger.Infof("Exiting icmp routine\n")
			return
		case p := <-icmpPkts:
			logger.Infof("I see packet: %v", p.Packet)
			p.SetVerdict(netfilter.NF_ACCEPT)
		}
	}
}
