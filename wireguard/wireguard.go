package wireguard

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	_type          = "WireGuard"
	serverKeysPath = "/etc/wireguard/"
	interfaceName  = "wg0"
)

var (
	endPoint   string
	listenPort = int(5253)
)

// Bandwidth ...
type Bandwidth struct {
	upload   int64
	download int64
}

// Keys ...
type Keys struct {
	PrivateKey wgtypes.Key
	PublicKey  wgtypes.Key
}

// WireGuard ...
type WireGuard struct {
	client     *wgctrl.Client
	port       uint16
	ip         net.IP
	protocol   string
	encryption string
}

// NewWireGuard ...
func NewWireGuard(port uint16, ip net.IP, protocol, encryption string) (*WireGuard, error) {
	client, err := wgctrl.New()
	if err != nil {
		log.Println(err)
		return &WireGuard{}, err
	}
	return &WireGuard{
		client:     client,
		port:       port,
		ip:         ip,
		protocol:   protocol,
		encryption: encryption,
	}, nil
}

func (wg WireGuard) saveKeys(public, private wgtypes.Key) error {
	err := ioutil.WriteFile(serverKeysPath+"privkey", []byte(private.String()), os.ModePerm)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(serverKeysPath+"pubkey", []byte(public.String()), os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func (wg WireGuard) generateServerKeys() (Keys, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Keys{}, err
	}
	publicKey := privateKey.PublicKey()

	fmt.Println("PrivateKey: ", privateKey)
	fmt.Println("PublicKey: ", publicKey)

	return Keys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func (wg WireGuard) setNATRouting() error {
	ipt, err := iptables.New()
	if err != nil {
		fmt.Println("err: ", err)
		return err
	}
	err = ipt.AppendUnique("filter", "FORWARD", "-i", interfaceName, "-j", "ACCEPT")
	if err != nil {
		return err
	}
	err = ipt.AppendUnique("nat", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
	if err != nil {
		return err
	}
	err = ipt.AppendUnique("filter", "FORWARD", "-o", interfaceName, "-j", "ACCEPT")
	if err != nil {
		return err
	}
	return nil
}

func (wg WireGuard) addWireGuardDevice() error {
	dev, _ := wg.client.Device(interfaceName)
	if dev != nil {
		cmmd := exec.Command("sh", "-c", fmt.Sprintf("ip link del dev %s ", interfaceName))
		_ = cmmd.Run()
	}
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ip link add dev %s type wireguard", interfaceName))
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("sh", "-c", fmt.Sprintf("ip -4 address add 10.0.0.1/24 dev %s", interfaceName))
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("sh", "-c", fmt.Sprintf("ip link set mtu 1420 up dev %s", interfaceName))
	return cmd.Run()
}

// Init ...
func (wg WireGuard) Init() error {
	log.Printf("Initializing the WireGuard server")

	if err := wg.addWireGuardDevice(); err != nil {
		return err
	}
	return wg.setNATRouting()
}

func (wg WireGuard) generateConfig() (wgtypes.Config, error) {
	keys, err := wg.generateServerKeys()
	if err != nil {
		return wgtypes.Config{}, err
	}
	if err := wg.saveKeys(keys.PublicKey, keys.PrivateKey); err != nil {
		return wgtypes.Config{}, err
	}
	return wgtypes.Config{
		PrivateKey:   &keys.PrivateKey,
		ListenPort:   &listenPort,
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{},
	}, nil
}

// Start ...
func (wg WireGuard) Start() error {
	cfg, err := wg.generateConfig()
	if err != nil {
		return err
	}

	return wg.client.ConfigureDevice(interfaceName, cfg)
}

// Stop ...
func (wg WireGuard) Stop() error {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ip link del dev %s", interfaceName))
	err := cmd.Run()
	ipt, _ := iptables.New()
	_ = ipt.Delete("filter", "FORWARD", "-i", interfaceName, "-j", "ACCEPT")
	_ = ipt.Delete("nat", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
	_ = ipt.Delete("filter", "FORWARD", "-o", interfaceName, "-j", "ACCEPT")
	return err
}

// Type ...
func (wg WireGuard) Type() string {
	return _type
}

// Encryption ...
func (wg WireGuard) Encryption() string {
	return wg.encryption
}

func (wg WireGuard) generateAllowedIP() ([]net.IPNet, error) {
	var allowedIPs []net.IP
	dev, err := wg.client.Device(interfaceName)
	if err != nil {
		return []net.IPNet{}, err
	}
	for _, peer := range dev.Peers {
		allowedIPs = append(allowedIPs, peer.AllowedIPs[0].IP)
	}
	for i := 2; i < 255; i++ {
		ip := net.IPv4(byte(10), byte(0), byte(0), byte(i))
		if !contains(allowedIPs, ip) {
			ipMask := net.IPv4Mask(byte(255), byte(255), byte(255), byte(255))
			return []net.IPNet{{IP: ip, Mask: ipMask}}, nil
		}
	}
	return []net.IPNet{}, fmt.Errorf("server is busy")
}

// GenerateClientKey ...
func (wg WireGuard) GenerateClientKey(pubkey string) ([]byte, error) {
	publicKey, err := wgtypes.ParseKey(pubkey)
	if err != nil {
		return []byte{}, err
	}
	availableIP, err := wg.generateAllowedIP()
	if err != nil {
		return []byte{}, err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:  publicKey,
		AllowedIPs: availableIP,
	}
	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peer},
	}
	err = wg.client.ConfigureDevice(interfaceName, cfg)
	if err != nil {
		log.Println("err:", err)
		return []byte(""), err
	}
	dev, _ := wg.client.Device(interfaceName)

	allowedip := fmt.Sprint(peer.AllowedIPs[0].IP)
	clientCreds := fmt.Sprintf("PublicKey: %s\nIP: %s\nEndPoint: %s\nAllowedIPs:"+
		"0.0.0.0/0\nPersistentKeepAlive:21", dev.PublicKey.String(), allowedip, endPoint)
	return []byte(clientCreds), nil
}

// ClientList ...
func (wg WireGuard) ClientList() (map[string]Bandwidth, error) {

	clientsUsageMap := map[string]Bandwidth{}
	wgData, err := wg.client.Device(interfaceName)
	if err != nil {
		return clientsUsageMap, err
	}

	for _, peer := range wgData.Peers {
		pubkey := peer.PublicKey
		// timeSecs := peer.LastHandshakeTime
		usage := Bandwidth{upload: peer.ReceiveBytes, download: peer.TransmitBytes}
		if len(pubkey) > 0 && usage.download > 0 {
			clientsUsageMap[pubkey.String()] = usage
		}
	}
	return clientsUsageMap, nil
}

// DisconnectClient ...
func (wg WireGuard) DisconnectClient(pubkey string) error {
	publicKey, err := wgtypes.ParseKey(pubkey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey: publicKey,
		Remove:    true,
	}
	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peer},
	}
	err = wg.client.ConfigureDevice(interfaceName, cfg)
	if err != nil {
		log.Println("err:", err)
		return err
	}
	return nil
}

func contains(arr []net.IP, ip net.IP) bool {
	for _, a := range arr {
		if a.String() == ip.String() {
			return true
		}
	}
	return false
}
