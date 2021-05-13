package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/vishvananda/netlink"
)

func main() {
	gtp5g, err := netlink.LinkByName("gtp5g0")
	if err == nil {
		fmt.Printf("already exists\n")
		return
	}
	/* Link */
	laddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:2152")
	if err != nil {
		fmt.Printf("resolve udp addr error: %v\n", err)
		return
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fmt.Printf("listen udp error: %v\n", err)
		return
	}
	f, err := conn.File()
	if err != nil {
		fmt.Printf("file error: %v\n", err)
		return
	}
	la := netlink.NewLinkAttrs()
	la.Name = "gtp5g0"
	gtp5g = &netlink.Gtp5g{LinkAttrs: la, FD1: int(f.Fd())}
	err = netlink.LinkAdd(gtp5g)
	if err != nil {
		fmt.Printf("ould not add %s: %v\n", la.Name, err)
		return
	}
	/* QER */
	qer := netlink.Gtp5gQer{
		Id:       1,
		UlDlGate: 2,
		Mbr: netlink.Gtp5gMbr{
			UlHigh: 3,
			UlLow:  4,
			DlHigh: 5,
			DlLow:  6,
		},
		Gbr: netlink.Gtp5gGbr{
			UlHigh: 7,
			UlLow:  8,
			DlHigh: 9,
			DlLow:  10,
		},
		QerCorrId: 11,
		Rqi:       12,
		Qfi:       13,
		Ppi:       14,
		Rcsr:      15,
	}
	err = netlink.Gtp5gAddQer(gtp5g, &qer)
	if err != nil {
		fmt.Printf("qer add error: %v\n", err)
	}
	/* FAR */
	far := netlink.Gtp5gFar{
		Id:          1,
		ApplyAction: 2,
		FwdParam: &netlink.Gtp5gForwardingParameter{
			HdrCreation: &netlink.Gtp5gOuterHeaderCreation{
				Desp:         3,
				Teid:         4,
				PeerAddrIpv4: net.IPv4(5, 6, 7, 8),
				Port:         9,
			},
			FwdPolicy: &netlink.Gtp5gForwardingPolicy{
				Identifier: "10",
			},
		},
	}
	err = netlink.Gtp5gAddFar(gtp5g, &far)
	if err != nil {
		fmt.Printf("far add error: %v\n", err)
	}
	/* PDR */
	var precedence uint32
	var tosTrafficClass uint16
	var securityParamIdx uint32
	var flowLabel uint32
	var biId uint32
	var outerHdrRemoval uint8
	var farId uint32
	var qerId uint32
	var ueAddrIpv4 net.IP
	var roleAddrIpv4 net.IP
	precedence = 2
	tosTrafficClass = 29
	securityParamIdx = 30
	flowLabel = 31
	biId = 32
	outerHdrRemoval = 33
	farId = 1
	qerId = 1
	ueAddrIpv4 = net.IPv4(3, 4, 5, 6)
	roleAddrIpv4 = net.IPv4(34, 35, 36, 37)
	unixSockPath := "abcd"
	pdr := netlink.Gtp5gPdr{
		Id:         1,
		Precedence: &precedence,
		Pdi: &netlink.Gtp5gPdi{
			UeAddrIpv4: &ueAddrIpv4,
			FTeid: &netlink.Gtp5gLocalFTeid{
				Teid:         7,
				GtpuAddrIpv4: net.IPv4(8, 9, 10, 11),
			},
			Sdf: &netlink.Gtp5gSdfFilter{
				Rule: &netlink.Gtp5gIpFilterRule{
					Action:    12,
					Direction: 13,
					Proto:     14,
					Src:       net.IPv4(15, 16, 17, 18),
					Smask:     net.IPv4(255, 255, 255, 0),
					Dest:      net.IPv4(19, 20, 21, 22),
					Dmask:     net.IPv4(255, 255, 0, 0),
					SportList: []uint32{23, 24, 25},
					DportList: []uint32{26, 27, 28},
				},
				TosTrafficClass:  &tosTrafficClass,
				SecurityParamIdx: &securityParamIdx,
				FlowLabel:        &flowLabel,
				BiId:             &biId,
			},
		},
		OuterHdrRemoval: &outerHdrRemoval,
		FarId:           &farId,
		QerId:           &qerId,
		RoleAddrIpv4:    &roleAddrIpv4,
		UnixSockPath:    &unixSockPath,
	}
	err = netlink.Gtp5gAddPdr(gtp5g, &pdr)
	if err != nil {
		fmt.Printf("pdr add error: %v\n", err)
	}

	exit := make(chan bool)

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		exit <- true
	}()

	fmt.Printf("PRESS CTL-C TO EXIT: ")

	<-exit

	fmt.Printf("\n")

	err = netlink.Gtp5gDelPdr(gtp5g, &pdr)
	if err != nil {
		fmt.Printf("pdr del error: %v\n", err)
	}

	err = netlink.Gtp5gDelFar(gtp5g, &far)
	if err != nil {
		fmt.Printf("far del error: %v\n", err)
	}

	err = netlink.Gtp5gDelQer(gtp5g, &qer)
	if err != nil {
		fmt.Printf("qer del error: %v\n", err)
	}

	err = netlink.LinkDel(gtp5g)
	if err != nil {
		fmt.Printf("link del error %s: %v\n", la.Name, err)
		return
	}
}
