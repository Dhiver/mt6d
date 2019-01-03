package main

import (
	"container/list"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/google/logger"
	"github.com/spf13/viper"
)

const (
	configFileName = "config"
)

// A Profile describes an end-to-end MT6D communication stream
type Profile struct {
	SrcHost    string
	DstHost    string
	SessionKey []byte
}

// Profiles is a map of Profile
type Profiles map[string]Profile

// Ethers represents IP address to MAC address mappings
type Ethers map[string]net.HardwareAddr

// IP is an IP struct
type IP struct {
	IP    net.IP
	IPNet *net.IPNet
}

// Users represents hostname to IP address mappings
type Users map[string]IP

// Config represents the global MT6D configuration structure
type Config struct {
	Profiles Profiles
	Ethers   Ethers
	Users    Users
}

// KeyExchangeState is a code for the key exchange state
type KeyExchangeState int

type Route struct {
	obscuredSrcIPAddr net.IP
	obscuredDstIPAddr net.IP
	expirationTime    time.Time
}

type Routes struct {
	actives *list.List
}

// Idkg is used in the in-band key generation
type Idkg struct {
	temporalKey       []byte
	keyExpirationTime time.Time
	keyExchangeState  KeyExchangeState
}

// A Stream represents an end-to-end MT6D connection between two hosts
type Stream struct {
	srcIPAddr  IP
	srcMAC     net.HardwareAddr
	dstIPAddr  IP
	dstMAC     net.HardwareAddr
	sessionKey []byte
	idkg       Idkg
	Routes     Routes
}

// Streams is a map of Stream. The index is the name of the stream
type Streams map[string]Stream

func getRotationInterval(sk []byte) int64 {
	hsk := sha256.Sum256(sk)
	var hkeyToInt big.Int
	hkeyToInt.SetBytes(hsk[:])
	c1 := big.NewInt(config.GetInt64("rangeinterval"))
	c2 := big.NewInt(config.GetInt64("minimumrotationtime"))
	var divisor big.Int
	divisor.Mod(&hkeyToInt, c1)
	return divisor.Add(&divisor, c2).Int64()
}

func getRotationTime(ri int64) int64 {
	bigTime := big.NewInt(time.Now().Unix())
	rotationInterval := big.NewInt(ri)
	return bigTime.Div(bigTime, rotationInterval).Int64()
}

func computeObscuredAddr(ip IP, sk []byte, rt int64) net.IP {
	var toHash []byte

	rtBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(rtBuf, rt)
	rtBytes := rtBuf[:n]

	toHash = append(toHash, ip.IP...)
	toHash = append(toHash, sk...)
	toHash = append(toHash, rtBytes...)
	hash := sha256.Sum256(toHash)

	var obscuredIP []byte
	netPortion := ip.IPNet.IP[:8]
	obscuredIP = append(obscuredIP, netPortion...)
	obscuredIP = append(obscuredIP, hash[:8]...)
	return net.IP(obscuredIP)
}

func startRouteCleaner(erc <-chan Route) {
	for route := range erc {
		// unbind addrs from NICs
		logger.Infof("Unbinding addrs: %s and %s", route.obscuredSrcIPAddr.String(), route.obscuredDstIPAddr.String())
	}
}

func startRouteBinder(arc <-chan Route) {
	for route := range arc {
		// Bind addrs to NICs
		logger.Infof("Binding addrs: %s and %s", route.obscuredSrcIPAddr.String(), route.obscuredDstIPAddr.String())
	}
}

func (s *Stream) handle() {
	rotationChan := make(chan int64, 1)
	expiredRoutesChan := make(chan Route)
	activeRoutesChan := make(chan Route)

	rotationInterval := getRotationInterval(s.sessionKey)

	// sync RT
	go func() {
		tmpRT := getRotationTime(rotationInterval)
		rotationChan <- tmpRT
		rt := tmpRT
		for {
			for {
				if rt != tmpRT {
					break
				}
				rt = getRotationTime(rotationInterval)
			}
			rotationChan <- rt
			for {
				time.Sleep(time.Duration(rotationInterval) * time.Second)
				rt = getRotationTime(rotationInterval)
				rotationChan <- rt
			}
		}
	}()

	go startRouteCleaner(expiredRoutesChan)
	go startRouteBinder(activeRoutesChan)

	isInitialLoop := true
	for {
		rt := <-rotationChan

		// clean expired obscured addresses
		for e := s.Routes.actives.Back(); e != nil; e = e.Prev() {
			r := e.Value.(Route)
			if r.expirationTime.Before(time.Now().UTC()) { // if route expired
				expiredRoutesChan <- r // give order to unbind
				s.Routes.actives.Remove(e)
			}
		}

		// Compute obscured addrs
		expTime := time.Now().UTC().Add(time.Duration(rotationInterval) * time.Second)
		if isInitialLoop {
			// The first route will expire quickly in order to avoid having two routes bound to NICs
			expTime = time.Time{}
		}
		elem := s.Routes.actives.PushFront(
			Route{
				obscuredSrcIPAddr: computeObscuredAddr(s.srcIPAddr, s.sessionKey, rt),
				obscuredDstIPAddr: computeObscuredAddr(s.dstIPAddr, s.sessionKey, rt),
				expirationTime:    expTime,
			},
		)

		route := elem.Value.(Route)
		activeRoutesChan <- route // give order to bind
	}
}

func addrObscurer(streams *Streams) {

	for _, v := range *streams {
		// One goroutine per stream
		go v.handle()

	}

	// Mutate profiles (generate new obscured addresses for each stream)
	// Create new external route using internal route addresses for hash (this will be used by the packetListener to identify the routes)
}

func packetListener() {
	// TODO: open TAP interface

	// TODO: Handle packets
	// RS and RA first
	// if RA, MTU ajusted
	// if RS, identifiying info removed
	// else, check if route exists
	// if not -> drop
	// check if incoming or to be send based on the IPv6 addresses
	// A packet containing hashed addresses indicates that the packet originated from the public network and should be extracted from its tunnel and forwarded to the end host.
	// A packet containing true addresses indicates that it was received from a protected host and should be tunneled before being forwarded through the public network
	// then remaining ICMPv6 packet types are handled
	// NS -> NA
	// ...
}

var (
	config *viper.Viper
)

func main() {
	// Retreive config
	config = viper.New()
	config.SetConfigType("yaml")
	config.AddConfigPath(".")
	config.SetConfigName(configFileName)
	if err := config.ReadInConfig(); err != nil {
		panic(fmt.Sprintf("could not parse configuration file: %s", err))
	}

	// Set up logging
	defer logger.Init("default", config.GetBool("logverbose"), false, ioutil.Discard).Close()
	logger.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)

	// retrieve profiles
	profiles := make(Profiles)
	for k := range config.GetStringMap("profiles") {
		c := config.GetStringMapString(fmt.Sprintf("profiles.%s", k))
		sk, err := base64.StdEncoding.DecodeString(c["sessionkey"])
		if err != nil {
			logger.Fatalf("could not decode session key: %s", err)
		}
		profiles[k] = Profile{
			SrcHost:    c["srchost"],
			DstHost:    c["dsthost"],
			SessionKey: sk,
		}
	}

	ethers := make(Ethers)
	var err error
	for k, v := range config.GetStringMapString("ethers") {
		ethers[k], err = net.ParseMAC(v)
		if err != nil {
			logger.Fatalf("could not parse mac addr: %s", err)
		}
	}

	users := make(Users)
	for k, v := range config.GetStringMapString("users") {
		ip, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			logger.Fatalf("could not parse IP: %s", err)
		}
		users[k] = IP{
			IP:    ip,
			IPNet: ipnet,
		}
	}

	c := Config{
		Profiles: profiles,
		Ethers:   ethers,
		Users:    users,
	}

	// TODO: Init firewall

	// Init streams
	streams := make(Streams)

	// Populate streams for each profile
	for k, v := range c.Profiles {
		logger.Infof("init stream %s", k)
		streams[k] = Stream{
			srcIPAddr:  c.Users[v.SrcHost],
			srcMAC:     c.Ethers[c.Users[v.SrcHost].IP.String()],
			dstIPAddr:  c.Users[v.DstHost],
			dstMAC:     c.Ethers[c.Users[v.DstHost].IP.String()],
			sessionKey: v.SessionKey,
			Routes: Routes{
				actives: list.New(),
			},
		}
	}

	// start address obscurer
	addrObscurer(&streams)

	// start packet listener
	packetListener()

	// idle waiting keyboard interupt
	end := make(chan bool)
	<-end
}
