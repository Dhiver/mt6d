package main

import (
	"context"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/logger"
)

var (
	serializeOptions = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
)

func icmpv6NeedModification(t uint8) bool {
	switch t {
	case
		layers.ICMPv6TypeDestinationUnreachable,
		layers.ICMPv6TypePacketTooBig,
		layers.ICMPv6TypeTimeExceeded,
		layers.ICMPv6TypeParameterProblem:
		return true
	}
	return false
}

func handleICMPPkt(p netfilter.NFPacket) {
	logger.Infof("ICMP, accepted, I see packet: %v", p.Packet)
	p.SetVerdict(netfilter.NF_ACCEPT)
	/*
		icmpv6Layer := p.Packet.Layer(layers.LayerTypeICMPv6)
		if icmpv6Layer == nil {
			p.SetVerdict(netfilter.NF_DROP)
			return
		}

		//var newPkt []byte
		icmpv6Pkt, _ := icmpv6Layer.(*layers.ICMPv6)
		logger.Infof("ICMP typecode: %s\n", icmpv6Pkt.TypeCode.String())
		logger.Infof("ICMP Packet is : %s\n", p.Packet)
		if icmpv6Pkt.TypeCode.Type() == layers.ICMPv6TypeRouterAdvertisement {
			// Generate new RA with reduced MTU and MAC of MT6D gateway (if any)
			// We only need to set the MTU because we don't have a MT6D gateway
			logger.Infof("ICMP routine: I see an ICMPv6 RA\n")


				var ipLayer layers.IPv6
				var icmpLayer layers.ICMPv6
				var raLayer layers.ICMPv6RouterAdvertisement

				parser := gopacket.NewDecodingLayerParser(
					layers.LayerTypeIPv6,
					&ipLayer,
					&icmpLayer,
					&raLayer,
				)
				foundLayerTypes := []gopacket.LayerType{}
				if err := parser.DecodeLayers(p.Packet.Data(), &foundLayerTypes); err != nil {
					logger.Fatalf("could not decode some layers: %s\n", err)
				}

				newIPLayer := &layers.IPv6{
					Version:    6,
					HopLimit:   64,
					NextHeader: layers.IPProtocolICMPv6,
				}
				newICMPLayer := &layers.ICMPv6{
					TypeCode: layers.ICMPv6TypeRouterAdvertisement,
				}
				newRALayer := layers.ICMPv6RouterAdvertisement{}

				// keep old RA values
				for _, layerType := range foundLayerTypes {
					switch layerType {
					case layers.LayerTypeIPv6:
						newIPLayer.SrcIP = ipLayer.SrcIP
						newIPLayer.DstIP = ipLayer.DstIP
					case layers.LayerTypeICMPv6NeighborAdvertisement:
						newRALayer.ReachableTime = raLayer.ReachableTime
						newRALayer.RetransTimer = raLayer.RetransTimer
						newRALayer.RouterLifetime = raLayer.RouterLifetime
						newRALayer.Flags = raLayer.Flags
						newRALayer.HopLimit = raLayer.HopLimit
						newRALayer.Options = raLayer.Options
					}
				}

				// Adjust MTU if set
				for i, opt := range newRALayer.Options {
					if opt.Type == layers.ICMPv6OptMTU {
						// TOCHECK
						mtu := make([]byte, 6)
						binary.LittleEndian.PutUint32(mtu, uint32(MTU))
						newRALayer.Options[i].Data = mtu
					}
				}

				if err := newICMPLayer.SetNetworkLayerForChecksum(newIPLayer); err != nil {
					logger.Fatalf("could not set network layer for checksum: %s", err)
				}
				raBuf := gopacket.NewSerializeBuffer()
				if err := newRALayer.SerializeTo(raBuf, serializeOptions); err != nil {
					logger.Fatalf("could not serialize new RA layer: %s", err)
				}
				raPayload := gopacket.Payload(raBuf.Bytes())

				buffer := gopacket.NewSerializeBuffer()
				if err := gopacket.SerializeLayers(buffer, serializeOptions,
					newIPLayer,
					newICMPLayer,
					raPayload); err != nil {
					logger.Fatalf("could not serialize new RA packet: %s", err)
				}

				newPkt = buffer.Bytes()


		} else if icmpv6Pkt.TypeCode.Type() == layers.ICMPv6TypeRouterSolicitation {
			// RS
			// TODO: Generate new RS with MAC of MT6D gateway
			logger.Infof("ICMP routine: I see an ICMPv6 RS\n")


				newEthLayer := &layers.Ethernet{
					SrcMAC:       net.HardwareAddr{}, // ???
					DstMAC:       net.HardwareAddr{}, // ???
					EthernetType: layers.EthernetTypeIPv6,
				}
				newIPLayer := &layers.IPv6{
					Version:    6,
					HopLimit:   64,
					NextHeader: layers.IPProtocolICMPv6,
				}
				newICMPLayer := &layers.ICMPv6{
					TypeCode: layers.ICMPv6TypeRouterSolicitation,
				}
				newRSLayer := layers.ICMPv6RouterSolicitation{}

				if err := newICMPLayer.SetNetworkLayerForChecksum(newIPLayer); err != nil {
					logger.Fatalf("could not set network layer for checksum: %s", err)
				}
				rsBuf := gopacket.NewSerializeBuffer()
				if err := newRSLayer.SerializeTo(rsBuf, serializeOptions); err != nil {
					logger.Fatalf("could not serialize new RS layer: %s", err)
				}
				rsPayload := gopacket.Payload(rsBuf.Bytes())

				buffer := gopacket.NewSerializeBuffer()
				if err := gopacket.SerializeLayers(buffer, serializeOptions,
					newEthLayer,
					newIPLayer,
					newICMPLayer,
					rsPayload); err != nil {
					logger.Fatalf("could not serialize new RS packet: %s", err)
				}

				newPkt = buffer.Bytes()


		} else if icmpv6NeedModification(icmpv6Pkt.TypeCode.Type()) {
			logger.Infof("ICMP routine: this packet need some changes\n")
			// TODO: replace route addresses with stream addresses in ICMP payload (original packet)
			// TODO: Reduce MTU if included in packet
			// TODO: Change destination address to true address of host that sent original packet
		}


		//p.SetVerdictWithPacket(netfilter.NF_ACCEPT, newPkt)
	*/
}

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
			go handleICMPPkt(p)
		}
	}
}
