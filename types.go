package main

import (
	"net"
)

// IP is an IP struct
type IP struct {
	IP    net.IP
	IPNet *net.IPNet
}

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

// Hostnames represents hostname to IP address mappings
type Hostnames map[string]IP
