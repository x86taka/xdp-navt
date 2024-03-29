package coreelf_test

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/x86taka/xdp-navt/pkg/coreelf"
)

var payload = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

func generateIPv4UDPInput(t *testing.T) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	iph := &layers.IPv4{
		Version: 4, Protocol: layers.IPProtocolUDP, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
		SrcIP: net.IP{192, 168, 1, 5}, DstIP: net.IP{1, 1, 1, 1},
	}
	udph := &layers.UDP{
		SrcPort: 1234,
		DstPort: 80,
	}
	udph.SetNetworkLayerForChecksum(iph)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts,

		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x01}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x02}, EthernetType: layers.EthernetTypeDot1Q},
		&layers.Dot1Q{VLANIdentifier: 1000, Type: layers.EthernetTypeIPv4},
		iph,
		udph,
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func generateIPv4UDPOutput(t *testing.T) []byte {

	t.Helper()

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	iph := &layers.IPv4{
		Version: 4, Protocol: layers.IPProtocolUDP, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
		SrcIP: net.IP{10, 10, 1, 5}, DstIP: net.IP{1, 1, 1, 1},
	}
	udph := &layers.UDP{
		SrcPort: 1234,
		DstPort: 80,
	}
	udph.SetNetworkLayerForChecksum(iph)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts,
		//90:1b:0e:63:aa:7f														ec:0d:9a:fe:cf:1e
		&layers.Ethernet{SrcMAC: []byte{0x90, 0x1b, 0x0e, 0x63, 0xaa, 0x7f}, DstMAC: []byte{0xec, 0x0d, 0x9a, 0xfe, 0xcf, 0x1e}, EthernetType: layers.EthernetTypeDot1Q},
		&layers.Dot1Q{VLANIdentifier: 98, Type: layers.EthernetTypeIPv4},
		iph,
		udph,
		gopacket.Payload(payload),
	)
	//BC:24:11:B0:06:80
	if err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

type XdpMd struct {
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}

func ebpfTestRun(input []byte, prog *ebpf.Program, xdpctx XdpMd) (uint32, []byte, error) {
	xdpOut := XdpMd{}
	var output []byte
	if len(input) > 0 {
		output = make([]byte, len(input)+256+2)
	}
	opts := ebpf.RunOptions{
		Data:       input,
		DataOut:    output,
		Context:    xdpctx,
		ContextOut: &xdpOut,
	}
	ret, err := prog.Run(&opts)
	if err != nil {
		return ret, nil, fmt.Errorf("test program: %w", err)
	}
	return ret, opts.DataOut, nil
}

func TestXDPProg(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	objs, err := coreelf.ReadCollection()
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("%+v\n", verr)
		} else {
			t.Fatal(err)
		}
	}
	defer objs.Close()

	input := generateIPv4UDPInput(t)
	xdpmd := XdpMd{
		Data:           0,
		DataEnd:        uint32(len(input)),
		IngressIfindex: 3,
	}

	ret, got, err := ebpfTestRun(input, objs.XdpProg, xdpmd)
	if err != nil {
		t.Error(err)
	}

	// retern code should be XDP_REDIRECT
	if ret != 3 {
		t.Errorf("got %d want %d", ret, 3)
	}

	// check output
	want := generateIPv4UDPOutput(t)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Logf("input: %x", input)
		t.Logf("output: %x", got)
		t.Logf("wantoutput: %x", want)
		t.Errorf("output mismatch (-want +got):\n%s", diff)
	}
}
