package netlink

import (
	//"fmt"
	"encoding/binary"
	"net"
	"unsafe"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

type Gtp5gMbr struct {
	UlHigh uint32
	UlLow  uint8
	DlHigh uint32
	DlLow  uint8
}

type Gtp5gGbr struct {
	UlHigh uint32
	UlLow  uint8
	DlHigh uint32
	DlLow  uint8
}

type Gtp5gQer struct {
	Id             uint32
	UlDlGate       uint8
	Mbr            Gtp5gMbr
	Gbr            Gtp5gGbr
	QerCorrId      uint32
	Rqi            uint8
	Qfi            uint8
	Ppi            uint8
	Rcsr           uint8
	RelatedPdrList []uint16
}

type Gtp5gOuterHeaderCreation struct {
	Desp         uint16
	Teid         uint32
	PeerAddrIpv4 net.IP
	Port         uint16
}

type Gtp5gForwardingPolicy struct {
	Identifier string
}

type Gtp5gForwardingParameter struct {
	HdrCreation *Gtp5gOuterHeaderCreation
	FwdPolicy   *Gtp5gForwardingPolicy
}

type Gtp5gFar struct {
	Id             uint32
	ApplyAction    uint8
	FwdParam       *Gtp5gForwardingParameter
	RelatedPdrList []uint16
}

type Gtp5gLocalFTeid struct {
	Teid         uint32
	GtpuAddrIpv4 net.IP
}
type Gtp5gIpFilterRule struct {
	Action    uint8
	Direction uint8
	Proto     uint8
	Src       net.IP
	Smask     net.IP
	Dest      net.IP
	Dmask     net.IP
	SportList []uint32
	DportList []uint32
}

type Gtp5gSdfFilter struct {
	Rule             *Gtp5gIpFilterRule
	TosTrafficClass  *uint16
	SecurityParamIdx *uint32
	FlowLabel        *uint32
	BiId             *uint32
}

type Gtp5gPdi struct {
	UeAddrIpv4 *net.IP
	FTeid      *Gtp5gLocalFTeid
	Sdf        *Gtp5gSdfFilter
}

type Gtp5gPdr struct {
	Id              uint16
	Precedence      *uint32
	Pdi             *Gtp5gPdi
	OuterHdrRemoval *uint8
	FarId           *uint32
	QerId           *uint32
	RoleAddrIpv4    *net.IP
	UnixSockPath    *string
}

func gtp5gBuildPdrPayload(req *nl.NetlinkRequest, link Link, pdr *Gtp5gPdr) {
	req.AddData(nl.NewRtAttr(nl.GTP5G_LINK, nl.Uint32Attr(uint32(link.Attrs().Index))))
	req.AddData(nl.NewRtAttr(nl.GTP5G_PDR_ID, nl.Uint16Attr(pdr.Id)))
	if pdr.Precedence != nil {
		req.AddData(nl.NewRtAttr(nl.GTP5G_PDR_PRECEDENCE, nl.Uint32Attr(*pdr.Precedence)))
	}
	if pdr.OuterHdrRemoval != nil {
		req.AddData(nl.NewRtAttr(nl.GTP5G_OUTER_HEADER_REMOVAL, nl.Uint8Attr(*pdr.OuterHdrRemoval)))
	}
	if pdr.FarId != nil {
		req.AddData(nl.NewRtAttr(nl.GTP5G_PDR_FAR_ID, nl.Uint32Attr(*pdr.FarId)))
	}
	if pdr.QerId != nil {
		req.AddData(nl.NewRtAttr(nl.GTP5G_PDR_QER_ID, nl.Uint32Attr(*pdr.QerId)))
	}
	if pdr.Pdi != nil {
		pdi := nl.NewRtAttr(nl.GTP5G_PDR_PDI|int(nl.NLA_F_NESTED), nil)
		if pdr.Pdi.UeAddrIpv4 != nil {
			ueAddrIpv4 := nativeEndian.Uint32(pdr.Pdi.UeAddrIpv4.To4())
			pdi.AddChild(nl.NewRtAttr(nl.GTP5G_PDI_UE_ADDR_IPV4, nl.Uint32Attr(ueAddrIpv4)))
		}
		if pdr.Pdi.FTeid != nil {
			fTeid := nl.NewRtAttr(nl.GTP5G_PDI_F_TEID|int(nl.NLA_F_NESTED), nil)
			fTeid.AddChild(nl.NewRtAttr(nl.GTP5G_F_TEID_I_TEID, nl.Uint32Attr(pdr.Pdi.FTeid.Teid)))
			gtpuAddrIpv4 := nativeEndian.Uint32(pdr.Pdi.FTeid.GtpuAddrIpv4.To4())
			fTeid.AddChild(nl.NewRtAttr(nl.GTP5G_F_TEID_GTPU_ADDR_IPV4, nl.Uint32Attr(gtpuAddrIpv4)))
			pdi.AddChild(fTeid)
		}
		if pdr.Pdi.Sdf != nil {
			sdf := nl.NewRtAttr(nl.GTP5G_PDI_SDF_FILTER|int(nl.NLA_F_NESTED), nil)
			if pdr.Pdi.Sdf.Rule != nil {
				sdfDesc := nl.NewRtAttr(nl.GTP5G_SDF_FILTER_FLOW_DESCRIPTION|int(nl.NLA_F_NESTED), nil)
				sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_ACTION, nl.Uint8Attr(pdr.Pdi.Sdf.Rule.Action)))
				sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_DIRECTION, nl.Uint8Attr(pdr.Pdi.Sdf.Rule.Direction)))
				sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_PROTOCOL, nl.Uint8Attr(pdr.Pdi.Sdf.Rule.Proto)))
				srcIpv4 := nativeEndian.Uint32(pdr.Pdi.Sdf.Rule.Src.To4())
				sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_SRC_IPV4, nl.Uint32Attr(srcIpv4)))
				smaskIpv4 := nativeEndian.Uint32(pdr.Pdi.Sdf.Rule.Smask.To4())
				sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_SRC_MASK, nl.Uint32Attr(smaskIpv4)))
				if pdr.Pdi.Sdf.Rule.SportList != nil && len(pdr.Pdi.Sdf.Rule.SportList) > 0 {
					sportList := make([]byte, len(pdr.Pdi.Sdf.Rule.SportList)*4)
					for i := range pdr.Pdi.Sdf.Rule.SportList {
						var sport *uint32
						sport = (*uint32)(unsafe.Pointer(&sportList[i*4]))
						*sport = pdr.Pdi.Sdf.Rule.SportList[i]
					}
					sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_SRC_PORT, sportList))
				}
				destIpv4 := nativeEndian.Uint32(pdr.Pdi.Sdf.Rule.Dest.To4())
				sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_DEST_IPV4, nl.Uint32Attr(destIpv4)))
				dmaskIpv4 := nativeEndian.Uint32(pdr.Pdi.Sdf.Rule.Dmask.To4())
				sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_DEST_MASK, nl.Uint32Attr(dmaskIpv4)))
				if pdr.Pdi.Sdf.Rule.DportList != nil && len(pdr.Pdi.Sdf.Rule.DportList) > 0 {
					dportList := make([]byte, len(pdr.Pdi.Sdf.Rule.DportList)*4)
					for i := range pdr.Pdi.Sdf.Rule.DportList {
						var dport *uint32
						dport = (*uint32)(unsafe.Pointer(&dportList[i*4]))
						*dport = pdr.Pdi.Sdf.Rule.DportList[i]
					}
					sdfDesc.AddChild(nl.NewRtAttr(nl.GTP5G_FLOW_DESCRIPTION_DEST_PORT, dportList))
				}
				sdf.AddChild(sdfDesc)
			}
			if pdr.Pdi.Sdf.TosTrafficClass != nil {
				sdf.AddChild(nl.NewRtAttr(nl.GTP5G_SDF_FILTER_TOS_TRAFFIC_CLASS, nl.Uint16Attr(*pdr.Pdi.Sdf.TosTrafficClass)))
			}
			if pdr.Pdi.Sdf.SecurityParamIdx != nil {
				sdf.AddChild(nl.NewRtAttr(nl.GTP5G_SDF_FILTER_SECURITY_PARAMETER_INDEX, nl.Uint32Attr(*pdr.Pdi.Sdf.SecurityParamIdx)))
			}
			if pdr.Pdi.Sdf.FlowLabel != nil {
				sdf.AddChild(nl.NewRtAttr(nl.GTP5G_SDF_FILTER_FLOW_LABEL, nl.Uint32Attr(*pdr.Pdi.Sdf.FlowLabel)))
			}
			if pdr.Pdi.Sdf.BiId != nil {
				sdf.AddChild(nl.NewRtAttr(nl.GTP5G_SDF_FILTER_SDF_FILTER_ID, nl.Uint32Attr(*pdr.Pdi.Sdf.BiId)))
			}
			pdi.AddChild(sdf)
		}
		req.AddData(pdi)
	}
}

func gtp5gBuildFarPayload(req *nl.NetlinkRequest, link Link, far *Gtp5gFar) {
	req.AddData(nl.NewRtAttr(nl.GTP5G_LINK, nl.Uint32Attr(uint32(link.Attrs().Index))))
	req.AddData(nl.NewRtAttr(nl.GTP5G_FAR_ID, nl.Uint32Attr(far.Id)))
	if far.ApplyAction > 0 {
		req.AddData(nl.NewRtAttr(nl.GTP5G_FAR_APPLY_ACTION, nl.Uint8Attr(far.ApplyAction)))
	}
	if far.FwdParam != nil {
		fwdParam := nl.NewRtAttr(nl.GTP5G_FAR_FORWARDING_PARAMETER|int(nl.NLA_F_NESTED), nil)
		if far.FwdParam.HdrCreation != nil {
			hdrCreation := nl.NewRtAttr(nl.GTP5G_FORWARDING_PARAMETER_OUTER_HEADER_CREATION|int(nl.NLA_F_NESTED), nil)
			hdrCreation.AddChild(nl.NewRtAttr(nl.GTP5G_OUTER_HEADER_CREATION_DESCRIPTION, nl.Uint16Attr(far.FwdParam.HdrCreation.Desp)))
			hdrCreation.AddChild(nl.NewRtAttr(nl.GTP5G_OUTER_HEADER_CREATION_O_TEID, nl.Uint32Attr(far.FwdParam.HdrCreation.Teid)))
			peerAddrIpv4 := nativeEndian.Uint32(far.FwdParam.HdrCreation.PeerAddrIpv4.To4())
			hdrCreation.AddChild(nl.NewRtAttr(nl.GTP5G_OUTER_HEADER_CREATION_PEER_ADDR_IPV4, nl.Uint32Attr(peerAddrIpv4)))
			hdrCreation.AddChild(nl.NewRtAttr(nl.GTP5G_OUTER_HEADER_CREATION_PORT, nl.Uint16Attr(far.FwdParam.HdrCreation.Port)))
			fwdParam.AddChild(hdrCreation)
		}
		if far.FwdParam.FwdPolicy != nil {
			identifier := make([]byte, len(far.FwdParam.FwdPolicy.Identifier)+1)
			copy(identifier, []byte(far.FwdParam.FwdPolicy.Identifier))
			identifier[len(far.FwdParam.FwdPolicy.Identifier)] = 0
			fwdParam.AddChild(nl.NewRtAttr(nl.GTP5G_FORWARDING_PARAMETER_FORWARDING_POLICY, identifier))
		}
		req.AddData(fwdParam)
	}
}

func gtp5gBuildQerPayload(req *nl.NetlinkRequest, link Link, qer *Gtp5gQer) {
	req.AddData(nl.NewRtAttr(nl.GTP5G_LINK, nl.Uint32Attr(uint32(link.Attrs().Index))))
	req.AddData(nl.NewRtAttr(nl.GTP5G_QER_ID, nl.Uint32Attr(qer.Id)))
	req.AddData(nl.NewRtAttr(nl.GTP5G_QER_GATE, nl.Uint8Attr(qer.UlDlGate)))
	mbr := nl.NewRtAttr(nl.GTP5G_QER_MBR|int(nl.NLA_F_NESTED), nil)
	mbr.AddChild(nl.NewRtAttr(nl.GTP5G_QER_MBR_UL_HIGH32, nl.Uint32Attr(qer.Mbr.UlHigh)))
	mbr.AddChild(nl.NewRtAttr(nl.GTP5G_QER_MBR_UL_LOW8, nl.Uint8Attr(qer.Mbr.UlLow)))
	mbr.AddChild(nl.NewRtAttr(nl.GTP5G_QER_MBR_DL_HIGH32, nl.Uint32Attr(qer.Mbr.DlHigh)))
	mbr.AddChild(nl.NewRtAttr(nl.GTP5G_QER_MBR_DL_LOW8, nl.Uint8Attr(qer.Mbr.DlLow)))
	req.AddData(mbr)
	gbr := nl.NewRtAttr(nl.GTP5G_QER_GBR|int(nl.NLA_F_NESTED), nil)
	gbr.AddChild(nl.NewRtAttr(nl.GTP5G_QER_GBR_UL_HIGH32, nl.Uint32Attr(qer.Gbr.UlHigh)))
	gbr.AddChild(nl.NewRtAttr(nl.GTP5G_QER_GBR_UL_LOW8, nl.Uint8Attr(qer.Gbr.UlLow)))
	gbr.AddChild(nl.NewRtAttr(nl.GTP5G_QER_GBR_DL_HIGH32, nl.Uint32Attr(qer.Gbr.DlHigh)))
	gbr.AddChild(nl.NewRtAttr(nl.GTP5G_QER_GBR_DL_LOW8, nl.Uint8Attr(qer.Gbr.DlLow)))
	req.AddData(gbr)
	req.AddData(nl.NewRtAttr(nl.GTP5G_QER_CORR_ID, nl.Uint32Attr(qer.QerCorrId)))
	req.AddData(nl.NewRtAttr(nl.GTP5G_QER_RQI, nl.Uint8Attr(qer.Rqi)))
	req.AddData(nl.NewRtAttr(nl.GTP5G_QER_QFI, nl.Uint8Attr(qer.Qfi)))
	req.AddData(nl.NewRtAttr(nl.GTP5G_QER_PPI, nl.Uint8Attr(qer.Ppi)))
	req.AddData(nl.NewRtAttr(nl.GTP5G_QER_RCSR, nl.Uint8Attr(qer.Rcsr)))
}

func (h *Handle) Gtp5gAddPdr(link Link, pdr *Gtp5gPdr) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_ADD_PDR,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_EXCL|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildPdrPayload(req, link, pdr)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func Gtp5gAddPdr(link Link, pdr *Gtp5gPdr) error {
	return pkgHandle.Gtp5gAddPdr(link, pdr)
}

func (h *Handle) Gtp5gAddFar(link Link, far *Gtp5gFar) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}

	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_ADD_FAR,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_EXCL|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildFarPayload(req, link, far)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
	return nil
}

func Gtp5gAddFar(link Link, far *Gtp5gFar) error {
	return pkgHandle.Gtp5gAddFar(link, far)
}

func (h *Handle) Gtp5gAddQer(link Link, qer *Gtp5gQer) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}

	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_ADD_QER,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_EXCL|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildQerPayload(req, link, qer)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func Gtp5gAddQer(link Link, qer *Gtp5gQer) error {
	return pkgHandle.Gtp5gAddQer(link, qer)
}

func (h *Handle) Gtp5gModPdr(link Link, pdr *Gtp5gPdr) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_ADD_PDR,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_REPLACE|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildPdrPayload(req, link, pdr)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func Gtp5gModPdr(link Link, pdr *Gtp5gPdr) error {
	return pkgHandle.Gtp5gModPdr(link, pdr)
}

func (h *Handle) Gtp5gModFar(link Link, far *Gtp5gFar) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_ADD_FAR,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_REPLACE|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildFarPayload(req, link, far)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func Gtp5gModFar(link Link, far *Gtp5gFar) error {
	return pkgHandle.Gtp5gModFar(link, far)
}

func (h *Handle) Gtp5gModQer(link Link, qer *Gtp5gQer) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_ADD_QER,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_REPLACE|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildQerPayload(req, link, qer)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func Gtp5gModQer(link Link, qer *Gtp5gQer) error {
	return pkgHandle.Gtp5gModQer(link, qer)
}

func (h *Handle) Gtp5gDelPdr(link Link, pdr *Gtp5gPdr) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_DEL_PDR,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_EXCL|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildPdrPayload(req, link, pdr)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func Gtp5gDelPdr(link Link, pdr *Gtp5gPdr) error {
	return pkgHandle.Gtp5gDelPdr(link, pdr)
}

func (h *Handle) Gtp5gDelFar(link Link, far *Gtp5gFar) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_DEL_FAR,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_EXCL|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildFarPayload(req, link, far)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func Gtp5gDelFar(link Link, far *Gtp5gFar) error {
	return pkgHandle.Gtp5gDelFar(link, far)
}

func (h *Handle) Gtp5gDelQer(link Link, qer *Gtp5gQer) error {
	f, err := h.GenlFamilyGet(nl.GENL_GTP5G_NAME)
	if err != nil {
		return err
	}
	msg := &nl.Genlmsg{
		Command: nl.GTP5G_CMD_DEL_QER,
	}
	req := h.newNetlinkRequest(int(f.ID), unix.NLM_F_EXCL|unix.NLM_F_ACK)
	req.AddData(msg)
	gtp5gBuildQerPayload(req, link, qer)

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func Gtp5gDelQer(link Link, qer *Gtp5gQer) error {
	return pkgHandle.Gtp5gDelQer(link, qer)
}
