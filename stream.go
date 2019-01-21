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
	"github.com/google/gopacket/layers"
	"github.com/google/logger"
	"github.com/vishvananda/netlink"
)

type Route struct {
	ObscuredSrcIPAddr net.IP
	ObscuredDstIPAddr net.IP
	ExpirationTime    time.Time
	RuleHandle        uint64
}

// IsExpired determines if the route is expired according to the UTC time
func (r *Route) IsExpired() bool {
	return r.ExpirationTime.Before(time.Now().UTC())
}

type Routes struct {
	Head    *list.List
	Expired *list.List
}

func (rs *Routes) Active() Route {
	return rs.Head.Front().Next().Value.(Route)
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
	Nfqid      uint16
	SrcIPAddr  IP
	SrcMAC     net.HardwareAddr
	DstIPAddr  IP
	DstMAC     net.HardwareAddr
	SessionKey []byte
	Routes     Routes
	//idkg       Idkg
}

func (s *Stream) Init(nlk netlink.Link, nft *nftMt6d) error {
	// bind stream real dst addr to internal NIC
	netlkAddr, err := netlink.ParseAddr(fmt.Sprintf("%s/64", s.DstIPAddr.IP.String()))
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(nlk, netlkAddr); err != nil {
		return err
	}

	// creates permanent entry in the neighbor cache for the stream source IPv6 and MAC address
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    nlk.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           s.SrcIPAddr.IP,
		HardwareAddr: s.SrcMAC,
		Family:       netlink.FAMILY_V6,
	}); err != nil {
		return err
	}

	return nft.redirectToQ(s.SrcIPAddr.IP, s.DstIPAddr.IP, s.Nfqid)
}

func (s *Stream) CleanOldRoutes(extNlk netlink.Link, nft *nftMt6d) error {
	var prev *list.Element
	for e := s.Routes.Expired.Back(); e != nil; e = prev {
		prev = e.Prev()

		r := e.Value.(*Route)
		logger.Infof("This route is expired and to be removed: %+v\n", r)

		logger.Infof("Deleting rule via handle num %d\n", r.RuleHandle)
		if err := nft.deleteRule(r.RuleHandle); err != nil {
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
		ExpirationTime:    time.Now().UTC().Add(time.Duration(rt) * time.Second),
		RuleHandle:        RuleHandleNum,
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
	return nft.redirectToQ(obsDst, obsSrc, s.Nfqid)
}

// Streams is a map of Stream. The index is the name of the stream
type Streams map[string]Stream

func (s *Stream) Handle(ctx context.Context) {
	defer wg.Done()

	// TODO: Init structs
	// TODO: Open UDP socket for external comms
	// TODO: Bind to netfilter queue

	streamNfq, err := netfilter.NewNFQueue(s.Nfqid, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		logger.Fatalf("could not get netfilter queue: %s", err)
	}
	//defer streamNfq.Close() // Doesn't return.... ?

	pkts := streamNfq.GetPackets()

	for {
		select {
		case <-ctx.Done():
			logger.Infof("Exiting stream routine\n")
			return
		case p := <-pkts:
			handleStreamPkt(p, s)
		}
	}

}

// Flush clean all routes. There expiration time is set to 0 and CleanOldRoutes is called.
func (s *Stream) Flush(extNlk netlink.Link, nft *nftMt6d) error {
	// Set all active route expiration time to 0
	for e := s.Routes.Head.Back(); e != nil; e = e.Prev() {
		r := e.Value.(*Route)
		r.ExpirationTime = time.Time{}
	}
	s.Routes.MoveExpiredRoutes()
	return s.CleanOldRoutes(extNlk, nft)
}

func handleStreamPkt(p netfilter.NFPacket, s *Stream) {
	// TODO: determine the direction of the packet
	ip6Layer := p.Packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer == nil {
		p.SetVerdict(netfilter.NF_DROP)
		return
	}
	ip6Pkt, _ := ip6Layer.(*layers.IPv6)

	if ip6Pkt.SrcIP.Equal(s.SrcIPAddr.IP) && ip6Pkt.DstIP.Equal(s.DstIPAddr.IP) { // inbound
		logger.Infof("Inbound traffic from %s to %s\n", ip6Pkt.SrcIP.String(), ip6Pkt.DstIP.String())
		logger.Infof("Packet is: %v", p.Packet)
		// Check packet size to see if > MT6D MTU
		if p.Packet.Metadata().Length > MTU {
			// TODO: Send ICMPv6 "too big message"

			p.SetVerdict(netfilter.NF_DROP)
			return
		}

		// TODO: decaps and send to internal interface
		//payload := p.Packet.ApplicationLayer()

		// - TODO: decode packet
		// - TODO: send
		//n, err := intIfce.Write()
	} else { // outbound
		logger.Infof("Outbound traffic from %s to %s\n", ip6Pkt.SrcIP.String(), ip6Pkt.DstIP.String())
		logger.Infof("Packet is: %v", p.Packet)
		// TODO: encaps and send to external interface
	}

	p.SetVerdict(netfilter.NF_DROP)
	//newPkt := []byte{}
	//p.SetVerdictWithPacket(netfilter.NF_ACCEPT, newPkt)
}
