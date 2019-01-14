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

// MoveExpiredRoutes moves expired routes from the Head list to the Expired list
func (rs *Routes) MoveExpiredRoutes() {
	for e := rs.Head.Back(); e != nil; e = e.Prev() {
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

func (s *Stream) Setup(nlk netlink.Link, nft *nftMt6d) error {
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
	for e := s.Routes.Expired.Back(); e != nil; e = e.Prev() {
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
	logger.Infof("I handle a stream !\n")
}
