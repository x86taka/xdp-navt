package config

import "net"

// MacConfig holds MAC address configuration
type MacConfig struct {
	MyMac        net.HardwareAddr `json:"my_mac"`
	ToUpstream   net.HardwareAddr `json:"to_upstream"`   // QFX VRF (upstream side)
	ToDownstream net.HardwareAddr `json:"to_downstream"` // QFX VLAN 98 (downstream side)
}

// VlanConfig holds VLAN configuration
type VlanConfig struct {
	ManagementVlan uint16 `json:"management_vlan"`
	OutputVlan     uint16 `json:"output_vlan"`
}

// IPConfig holds IP network configuration
type IPConfig struct {
	InsideNetwork  net.IPNet `json:"inside_network"`
	OutsideNetwork net.IPNet `json:"outside_network"`
}

// Config represents the complete XDP-NAVT configuration
type Config struct {
	Mac  MacConfig  `json:"mac"`
	Vlan VlanConfig `json:"vlan"`
	IP   IPConfig   `json:"ip"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	myMac, _ := net.ParseMAC("90:1b:0e:63:aa:7f")
	toUpstream, _ := net.ParseMAC("ec:0d:9a:fe:cf:1c")   // QFX VRF (upstream)
	toDownstream, _ := net.ParseMAC("ec:0d:9a:fe:cf:1e") // QFX VLAN 98 (downstream)

	_, insideNet, _ := net.ParseCIDR("192.168.0.0/16")
	_, outsideNet, _ := net.ParseCIDR("10.0.0.0/24")

	return &Config{
		Mac: MacConfig{
			MyMac:        myMac,
			ToUpstream:   toUpstream,
			ToDownstream: toDownstream,
		},
		Vlan: VlanConfig{
			ManagementVlan: 0x062,
			OutputVlan:     98,
		},
		IP: IPConfig{
			InsideNetwork:  *insideNet,
			OutsideNetwork: *outsideNet,
		},
	}
}
