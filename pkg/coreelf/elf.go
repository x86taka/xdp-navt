package coreelf

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/x86taka/xdp-navt/pkg/config"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf xdp ../../src/xdp_prog.c -- -I/usr/include/x86_64-linux-gnu -I/usr/include -I./../../include -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wnull-character -g -c -O2 -D__KERNEL__

func ReadCollection() (*xdpObjects, error) {
	return ReadCollectionWithConfig(config.DefaultConfig())
}

func ReadCollectionWithConfig(cfg *config.Config) (*xdpObjects, error) {
	obj := &xdpObjects{}
	// TODO: BPF log level remove hardcoding. yaml in config?
	err := loadXdpObjects(obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 2,
			LogSize:  102400 * 1024,
		},
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Configure eBPF maps with provided configuration
	err = configureMaps(obj, cfg)
	if err != nil {
		obj.Close()
		return nil, errors.WithStack(err)
	}

	return obj, nil
}

// MacConfigBPF represents MAC configuration for eBPF
type MacConfigBPF struct {
	MyMac        [6]uint8
	ToUpstream   [6]uint8 // QFX VRF (upstream side)
	ToDownstream [6]uint8 // QFX VLAN 98 (downstream side)
}

// VlanConfigBPF represents VLAN configuration for eBPF
type VlanConfigBPF struct {
	ManagementVlan uint16
	OutputVlan     uint16
}

// IPConfigBPF represents IP configuration for eBPF
type IPConfigBPF struct {
	InsideNetwork  uint32
	OutsideNetwork uint32
}

func configureMaps(obj *xdpObjects, cfg *config.Config) error {
	key := uint32(0)

	// Configure MAC addresses
	macCfg := MacConfigBPF{}
	copy(macCfg.MyMac[:], cfg.Mac.MyMac)
	copy(macCfg.ToUpstream[:], cfg.Mac.ToUpstream)
	copy(macCfg.ToDownstream[:], cfg.Mac.ToDownstream)

	err := obj.MacConfigMap.Put(&key, &macCfg)
	if err != nil {
		return errors.WithStack(err)
	}

	// Configure VLAN settings
	vlanCfg := VlanConfigBPF{
		ManagementVlan: cfg.Vlan.ManagementVlan,
		OutputVlan:     cfg.Vlan.OutputVlan,
	}

	err = obj.VlanConfigMap.Put(&key, &vlanCfg)
	if err != nil {
		return errors.WithStack(err)
	}

	// Configure IP networks
	insideIP := cfg.IP.InsideNetwork.IP.To4()
	outsideIP := cfg.IP.OutsideNetwork.IP.To4()

	if insideIP == nil || outsideIP == nil {
		return errors.New("invalid IP configuration: only IPv4 is supported")
	}

	ipCfg := IPConfigBPF{
		InsideNetwork:  binary.BigEndian.Uint32(insideIP),
		OutsideNetwork: binary.BigEndian.Uint32(outsideIP),
	}

	err = obj.IpConfigMap.Put(&key, &ipCfg)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
