package main

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/logger"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
)

type Route struct {
	ObscuredSrcIPAddr net.IP
	ObscuredDstIPAddr net.IP
	ExpirationTime    time.Time
	NftRuleHandle     uint64
	NftChain          *nftables.Chain
}

// IsExpired determines if the route is expired according to the UTC time
func (r *Route) IsExpired() bool {
	return r.ExpirationTime.Before(time.Now().UTC())
}

type Routes struct {
	Head    *list.List
	Expired *list.List
}

func (rs *Routes) Active() *Route {
	fe := rs.Head.Front()
	if fe.Next() != nil {
		return fe.Next().Value.(*Route)
	}
	return fe.Value.(*Route)
}

func (rs *Routes) Dump() {
	fmt.Printf("ACTIVE routes: ")
	for e := rs.Head.Front(); e != nil; e = e.Next() {
		r := e.Value.(*Route)
		fmt.Printf("%v - ", *r)
	}
	fmt.Printf("\nEXPIRED routes: ")
	for e := rs.Expired.Front(); e != nil; e = e.Next() {
		r := e.Value.(*Route)
		fmt.Printf("%v - ", *r)
	}
	fmt.Printf("\n")
}

// MoveExpiredRoutes moves expired routes from the Head list to the Expired list
func (rs *Routes) MoveExpiredRoutes() {
	var prev *list.Element
	for e := rs.Head.Back(); e != nil; e = prev {
		prev = e.Prev()
		r := e.Value.(*Route)
		if r.IsExpired() {
			rs.Head.Remove(e)
			rs.Expired.PushFront(r)
		}
	}
}

// KeyExchangeState is a code for the key exchange state
type KeyExchangeState int

// Idkg is used in the in-band key generation
type Idkg struct {
	temporalKey       []byte
	keyExpirationTime time.Time
	keyExchangeState  KeyExchangeState
}

// A Stream represents an end-to-end MT6D connection between two hosts
type Stream struct {
	NfqOutID   uint16
	NfqInID    uint16
	SrcIPAddr  IP
	SrcMAC     net.HardwareAddr
	DstIPAddr  IP
	DstMAC     net.HardwareAddr
	SessionKey []byte
	Routes     Routes
	//idkg       Idkg
}

func (s *Stream) Init(nlk netlink.Link, nft *nftMt6d) error {
	// bind stream real source addr to internal NIC
	netlkAddr, err := netlink.ParseAddr(fmt.Sprintf("%s/64", s.SrcIPAddr.IP.String()))
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(nlk, netlkAddr); err != nil {
		return err
	}

	/*
		// creates permanent entry in the neighbor cache for the stream source IPv6 and MAC address (if MT6D gateway)
		if err := netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:    nlk.Attrs().Index, // set internal interface index
			State:        netlink.NUD_PERMANENT,
			IP:           s.DstIPAddr.IP, // set real dst IP addr
			HardwareAddr: s.DstMAC,       // set real dst MAC addr
			Family:       netlink.FAMILY_V6,
		}); err != nil {
			return err
		}
	*/

	// redirect outbound traffic to specific queue
	return nft.redirectToQ(s.SrcIPAddr.IP, s.DstIPAddr.IP, s.NfqOutID, nft.outputChain)
}

func (s *Stream) CleanOldRoutes(extNlk netlink.Link, nft *nftMt6d) error {
	var prev *list.Element
	for e := s.Routes.Expired.Back(); e != nil; e = prev {
		prev = e.Prev()

		r := e.Value.(*Route)
		logger.Infof("This route is expired and to be removed: %+v\n", r)

		logger.Infof("Deleting rule via handle num %d with chain: %s\n", r.NftRuleHandle, r.NftChain.Name)
		if err := nft.deleteRule(r.NftRuleHandle, r.NftChain); err != nil {
			return err
		}
		// unbind addr from interface
		logger.Infof("I unbind addr: %s\n", r.ObscuredSrcIPAddr.String())
		nlkAddr, err := netlink.ParseAddr(fmt.Sprintf("%s/64", r.ObscuredSrcIPAddr.String()))
		if err != nil {
			return err
		}
		if err := netlink.AddrDel(extNlk, nlkAddr); err != nil {
			return err
		}

		s.Routes.Expired.Remove(e)
	}

	s.Routes.MoveExpiredRoutes()
	return nil
}

func computeObscuredAddr(ip IP, sk []byte, salt int64) net.IP {
	saltBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(saltBuf, salt)
	saltBytes := saltBuf[:n]

	var toHash bytes.Buffer
	toHash.Write(ip.IP[8:])
	toHash.Write(sk)
	toHash.Write(saltBytes)

	hash := sha256.Sum256(toHash.Bytes())

	var obscuredIP bytes.Buffer
	obscuredIP.Write(ip.IPNet.IP[:8])
	obscuredIP.Write(hash[:8])

	return net.IP(obscuredIP.Bytes())
}

func (s *Stream) computeObscuredAddrs(salt int64) (net.IP, net.IP) {
	return computeObscuredAddr(s.SrcIPAddr, s.SessionKey, salt), computeObscuredAddr(s.DstIPAddr, s.SessionKey, salt)
}

// Mutate generated new hashed addresses
func (s *Stream) Mutate(inNlk, extNlk netlink.Link, nft *nftMt6d, salt, rt int64) error {
	// Create route with new hashed IPv6 addrs and expiration time
	obsSrc, obsDst := s.computeObscuredAddrs(salt)
	newRoute := &Route{
		ObscuredSrcIPAddr: obsSrc,
		ObscuredDstIPAddr: obsDst,
		ExpirationTime:    time.Now().UTC().Add(time.Duration(config.GetInt("addresslifetime")) * time.Second),
		NftRuleHandle:     RuleHandleNum,
		NftChain:          nft.inputChain,
	}

	logger.Infof("New route: %+v\n", *newRoute)

	// Add new route to linked list
	s.Routes.Head.PushFront(newRoute)

	// Bind route source address to external interface
	netlkAddr, err := netlink.ParseAddr(fmt.Sprintf("%s/64", obsSrc.String()))
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(extNlk, netlkAddr); err != nil {
		return err
	}

	// Add route nftables rule to direct route traffic into netfilter queue
	return nft.redirectToQ(obsDst, obsSrc, s.NfqInID, nft.inputChain)
}

// Streams is a map of Stream. The index is the name of the stream
type Streams map[string]Stream

func (s *Stream) Handle(ctx context.Context) {
	defer wg.Done()

	// TODO: Init structs
	// TODO: Open UDP socket for external comms

	logger.Infof("OUT is on queue ID: %d\n", s.NfqInID)
	inNfq, err := netfilter.NewNFQueue(s.NfqInID, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		logger.Fatalf("could not get netfilter queue: %s", err)
	}
	//defer inNfq.Close() // Doesn't return.... ?

	inPkts := inNfq.GetPackets()

	logger.Infof("IN is on queue ID: %d\n", s.NfqOutID)
	outNfq, err := netfilter.NewNFQueue(s.NfqOutID, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		logger.Fatalf("could not get netfilter queue: %s", err)
	}
	//defer outNfq.Close() // Doesn't return.... ?

	outPkts := outNfq.GetPackets()

	for {
		select {
		case <-ctx.Done():
			logger.Infof("Exiting stream routine\n")
			return
		case p := <-inPkts:
			go handleInPkt(p, s)
		case p := <-outPkts:
			go handleOutPkt(p, s)
		}
	}
}

// Flush cleans all routes. There expiration time is set to 0 and CleanOldRoutes is called.
func (s *Stream) Flush(extNlk netlink.Link, nft *nftMt6d) error {
	// Set all active route expiration time to 0
	for e := s.Routes.Head.Back(); e != nil; e = e.Prev() {
		r := e.Value.(*Route)
		r.ExpirationTime = time.Time{}
	}
	s.Routes.MoveExpiredRoutes()
	return s.CleanOldRoutes(extNlk, nft)
}

func handleOutPkt(p netfilter.NFPacket, s *Stream) { // from internal, encaps and send to external
	logger.Infof("OUT Pkt in queue: %v\n", p.Packet)
	p.SetVerdict(netfilter.NF_DROP)

	currentRoute := s.Routes.Active()

	srcUDPAddr, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[%s]:2345", currentRoute.ObscuredSrcIPAddr.String()))
	if err != nil {
		logger.Fatalf("could not parse UDP addr: %s", err)
	}
	dstUDPAddr, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[%s]:6789", currentRoute.ObscuredDstIPAddr.String()))
	if err != nil {
		logger.Fatalf("could not parse UDP addr: %s", err)
	}
	conn, err := net.DialUDP("udp6", srcUDPAddr, dstUDPAddr)
	if err != nil {
		logger.Fatalf("could not dial udp: %s", err)
	}
	defer conn.Close()

	origIPLayer := p.Packet.Layer(layers.LayerTypeIPv6)
	if origIPLayer == nil {
		return
	}
	ip, _ := origIPLayer.(*layers.IPv6)

	// Remove IP addresses from payload
	truncatedHeader := ip.LayerContents()[:8] // only keep the first 8 bytes of the original IPv6 header
	payload := append(truncatedHeader, ip.Payload...)

	if _, err = conn.Write(payload); err != nil {
		logger.Errorf("error while writing: %s", err)
	}
}

func handleInPkt(p netfilter.NFPacket, s *Stream) { // from external, decaps and send to internal
	logger.Infof("IN Pkt in queue: %v\n", p.Packet)

	icmpv6Layer := p.Packet.Layer(layers.LayerTypeICMPv6)
	if icmpv6Layer != nil {
		icmpv6Pkt, _ := icmpv6Layer.(*layers.ICMPv6)
		logger.Infof("accept ICMP typecode: %s\n", icmpv6Pkt.TypeCode.String())
		if icmpv6Pkt.TypeCode.Type() == layers.ICMPv6TypeNeighborSolicitation || icmpv6Pkt.TypeCode.Type() == layers.ICMPv6TypeNeighborAdvertisement {
			p.SetVerdict(netfilter.NF_ACCEPT)
			return
		}
	}
	p.SetVerdict(netfilter.NF_DROP)

	// TODO: handle NS, we can avoid it by netlink.NeighAdd() for dst obscured addr on each new route ?

	// TODO: if no UDP layer / application layer -> drop

	appLayer := p.Packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	/*
		// Check packet size to see if > MT6D MTU
		if p.Packet.Metadata().Length > MTU {
			// TODO: Send ICMPv6 "too big message"

			return
		}
	*/

	payload := appLayer.Payload()

	// Reconstruct truncated pkt
	var buf bytes.Buffer
	buf.Write(payload[:8])
	buf.Write(s.DstIPAddr.IP)
	buf.Write(s.SrcIPAddr.IP)
	buf.Write(payload[8:])

	decapsPkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
	logger.Infof("I received PKT: %v\n", decapsPkt)

	if _, err := intIfce.Write(buf.Bytes()); err != nil {
		logger.Errorf("error while writing: %s", err)
	}
}
