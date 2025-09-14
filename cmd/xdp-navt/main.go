package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"github.com/x86taka/xdp-navt/pkg/config"
	"github.com/x86taka/xdp-navt/pkg/coreelf"
	"github.com/x86taka/xdp-navt/pkg/version"
	"github.com/x86taka/xdp-navt/pkg/xdptool"
)

func main() {
	app := newApp(version.Version)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "xdp-navt"
	app.Version = version

	app.Usage = "Network Address and VLAN Translation with XDP"

	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringSliceFlag{
			Name:  "device",
			Value: &cli.StringSlice{"eth1"},
			Usage: "Adding a device to attach",
		},
		cli.StringFlag{
			Name:  "my-mac",
			Usage: "My MAC address (e.g., 90:1b:0e:63:aa:7f)",
		},
		cli.StringFlag{
			Name:  "upstream-mac",
			Usage: "Upstream MAC address - QFX VRF (e.g., ec:0d:9a:fe:cf:1c)",
		},
		cli.StringFlag{
			Name:  "downstream-mac",
			Usage: "Downstream MAC address - QFX VLAN 98 (e.g., ec:0d:9a:fe:cf:1e)",
		},
		cli.UintFlag{
			Name:  "management-vlan",
			Usage: "Management VLAN ID (default: 98, 0x62)",
		},
		cli.UintFlag{
			Name:  "output-vlan",
			Usage: "Output VLAN ID (default: 98, 0x62)",
		},
		cli.StringFlag{
			Name:  "inside-network",
			Usage: "Inside network CIDR (default: 192.168.0.0/16)",
		},
		cli.StringFlag{
			Name:  "outside-network",
			Usage: "Outside network CIDR (default: 10.0.0.0/24)",
		},
	}
	app.Action = run
	return app
}

func disposeDevice(devices []string) error {
	for _, dev := range devices {
		err := xdptool.Detach(dev)
		if err != nil {
			return errors.WithStack(err)
		}
		log.Println("detach device: ", dev)
	}
	return nil
}

func run(ctx *cli.Context) error {
	devices := ctx.StringSlice("device")
	log.Println(devices)

	// Build configuration from CLI arguments
	cfg, err := buildConfig(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	// get ebpf binary with configuration
	obj, err := coreelf.ReadCollectionWithConfig(cfg)
	if err != nil {
		return errors.WithStack(err)
	}

	//attach xdp
	for _, dev := range devices {
		err = xdptool.Attach(obj.XdpProg, dev)
		if err != nil {
			return errors.WithStack(err)
		}
		log.Println("attached device: ", dev)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	log.Println("XDP program successfully loaded and attached.")
	log.Println("Press CTRL+C to stop.")
	for {
		select {
		case <-signalChan:
			err := disposeDevice(devices)
			if err != nil {
				return errors.WithStack(err)
			}
			return nil
		}
	}

}

func buildConfig(ctx *cli.Context) (*config.Config, error) {
	cfg := config.DefaultConfig()

	// Override MAC addresses if provided
	if myMac := ctx.String("my-mac"); myMac != "" {
		mac, err := net.ParseMAC(myMac)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		cfg.Mac.MyMac = mac
	}

	if upstreamMac := ctx.String("upstream-mac"); upstreamMac != "" {
		mac, err := net.ParseMAC(upstreamMac)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		cfg.Mac.ToUpstream = mac
	}

	if downstreamMac := ctx.String("downstream-mac"); downstreamMac != "" {
		mac, err := net.ParseMAC(downstreamMac)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		cfg.Mac.ToDownstream = mac
	}

	// Override VLAN settings if provided
	if mgmtVlan := ctx.Uint("management-vlan"); mgmtVlan != 0 {
		cfg.Vlan.ManagementVlan = uint16(mgmtVlan)
	}

	if outputVlan := ctx.Uint("output-vlan"); outputVlan != 0 {
		cfg.Vlan.OutputVlan = uint16(outputVlan)
	}

	// Override IP networks if provided
	if insideNet := ctx.String("inside-network"); insideNet != "" {
		_, ipNet, err := net.ParseCIDR(insideNet)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		cfg.IP.InsideNetwork = *ipNet
	}

	if outsideNet := ctx.String("outside-network"); outsideNet != "" {
		_, ipNet, err := net.ParseCIDR(outsideNet)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		cfg.IP.OutsideNetwork = *ipNet
	}

	return cfg, nil
}
