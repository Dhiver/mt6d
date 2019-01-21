package main

import (
	"container/list"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"

	"github.com/google/logger"
	"github.com/google/nftables"
	"github.com/songgao/water"
	"github.com/spf13/viper"
)

const (
	configFileName = "config"
)

var (
	wg      sync.WaitGroup
	config  *viper.Viper
	intIfce *water.Interface

	MTU = 1400
)

func initStreams() (*Streams, error) {
	// retrieve profiles
	profiles := make(Profiles)
	for k := range config.GetStringMap("profiles") {
		c := config.GetStringMapString(fmt.Sprintf("profiles.%s", k))
		sk, err := base64.StdEncoding.DecodeString(c["sessionkey"])
		if err != nil {
			return nil, err
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
			return nil, err
		}
	}

	hostnames := make(Hostnames)
	for k, v := range config.GetStringMapString("hostnames") {
		ip, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}
		hostnames[k] = IP{
			IP:    ip,
			IPNet: ipnet,
		}
	}

	// Init streams
	streams := make(Streams)

	// Populate streams for each profile
	nfqid := uint16(2) // netfilter queue ID 1 is for icmpv6 traffic
	for k, v := range profiles {
		logger.Infof("init stream %s", k)
		streams[k] = Stream{
			Nfqid:      nfqid,
			SrcIPAddr:  hostnames[v.SrcHost],
			SrcMAC:     ethers[hostnames[v.SrcHost].IP.String()],
			DstIPAddr:  hostnames[v.DstHost],
			DstMAC:     ethers[hostnames[v.DstHost].IP.String()],
			SessionKey: v.SessionKey,
			Routes: Routes{
				Head:    list.New(),
				Expired: list.New(),
			},
		}
		nfqid++
	}
	return &streams, nil
}

func main() {
	// read conf
	config = viper.New()
	config.SetConfigType("yaml")
	config.AddConfigPath(".")
	config.SetConfigName(configFileName)
	if err := config.ReadInConfig(); err != nil {
		logger.Fatalf("could not parse configuration file: %s", err)
	}

	// set up logging
	var logFile io.Writer
	logFile = ioutil.Discard
	if logPath := config.GetString("logfile"); logPath != "" {
		lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err != nil {
			logger.Fatalf("could not open log file '%s': %s", logPath, err)
		}
		defer lf.Close()
		logFile = lf
	}
	defer logger.Init("default", config.GetBool("logverbose"), false, logFile).Close()
	logger.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)

	// signal registration
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	// synchronization of routines
	defer wg.Wait() // will wait for all routine to be done before exiting
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // inform routines to stop

	streams, err := initStreams()
	if err != nil {
		logger.Fatalf("could not init streams: %s", err)
	}

	var nftc nftables.Conn

	// Open internal interface
	wconfig := water.Config{
		DeviceType: water.TAP,
	}
	wconfig.Name = config.GetString("internalnic")

	intIfce, err = water.New(wconfig)
	if err != nil {
		logger.Fatalf("could not create internal interface: %s", err)
	}

	logger.Info("MT6D starting...")

	// start rehash routine
	go rehashRoutine(ctx, &nftc, streams)
	wg.Add(1)

	// start ICMP routine
	go icmpRoutine(ctx)
	wg.Add(1)

	// start stream thread(s)
	for k, s := range *streams {
		logger.Infof("starting handler for stream: %s", k)
		go s.Handle(ctx)
		wg.Add(1)
	}

	// wait for termination signal
	<-signalChan
	fmt.Printf("Interrupt signal detected\n")
}
