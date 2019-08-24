package wireguard

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	hub "github.com/sentinel-official/hub/types"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	Type           = "WireGuard"
	serverKeysPath = "/etc/wireguard/"
	_interface     = "wg0"
)

var (
	endPoint   string
	listenPort = 5253
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
type PublicIP struct {
	IP string `json:"ip"`
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

func (wg WireGuard) generateKeys() (Keys, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Keys{}, err
	}
	publicKey := privateKey.PublicKey()
	return Keys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func (wg WireGuard) setNATRouting() error {
	cmd := cmdSetNATRouting(_interface)
	return cmd.Run()
}

func (wg WireGuard) addWireGuardDevice() error {
	fmt.Print("\nAdding wireguard device ...\n")
	dev, _ := wg.client.Device(_interface)
	if dev != nil {
		cmd := cmdDeleteDevLink(_interface)
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	cmd := cmdAddDevLink(_interface, "wireguard")
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = cmdAddDevAddressIPv4(_interface, "10.0.0.1/24")
	if err := cmd.Run(); err != nil {
		log.Println("3", err)
		return err
	}
	cmd = cmdSetDevMTU(_interface, 1420)
	return cmd.Run()
}

// Init ...
func (wg WireGuard) Init() error {
	fmt.Printf("\nInitializing the WireGuard server")
	if err := wg.addWireGuardDevice(); err != nil {
		return err
	}
	resp, err := http.Get("https://api.ipify.org/?format=json")
	if err != nil {
		return err
	}
	var res PublicIP
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}
	defer resp.Body.Close()
	endPoint = fmt.Sprintf("%s:%d", res.IP, listenPort)
	return wg.setNATRouting()
}

func (wg WireGuard) generateConfig() (wgtypes.Config, error) {
	keys, err := wg.generateKeys()
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
	fmt.Print("\nStarting WireGuard Device ...\n")
	cfg, err := wg.generateConfig()
	if err != nil {
		return err
	}

	return wg.client.ConfigureDevice(_interface, cfg)
}

// Stop ...
func (wg WireGuard) Stop() error {
	fmt.Print("\nStopping WireGuard Device ...\n")
	cmd := cmdDeleteDevLink(_interface)
	return cmd.Run()
}

// Type ...
func (wg WireGuard) Type() string {
	return Type
}

// Encryption ...
func (wg WireGuard) Encryption() string {
	return wg.encryption
}

func (wg WireGuard) generateAllowedIP() ([]net.IPNet, error) {
	var allowedIPs []net.IP
	dev, err := wg.client.Device(_interface)
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
func (wg WireGuard) GenerateClientKey() ([]byte, error) {
	fmt.Print("\nAdding Peer to WireGuard Device ...\n")
	keys, err := wg.generateKeys()
	if err != nil {
		return []byte{}, err
	}
	availableIP, err := wg.generateAllowedIP()
	if err != nil {
		return []byte{}, err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:  keys.PublicKey,
		AllowedIPs: availableIP,
	}
	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peer},
	}
	err = wg.client.ConfigureDevice(_interface, cfg)
	if err != nil {
		log.Println("err:", err)
		return []byte(""), err
	}
	dev, _ := wg.client.Device(_interface)

	allowedIP := fmt.Sprint(peer.AllowedIPs[0].IP)
	clientConfig := fmt.Sprintf(clientConfigTemplate, keys.PrivateKey.String(), allowedIP,
		dev.PublicKey.String(), endPoint)
	return []byte(clientConfig), nil
}

// ClientsList ...
func (wg WireGuard) ClientsList() (map[string]hub.Bandwidth, error) {
	// fmt.Print("\nGetting clients usage list ...\n")
	clientsUsageMap := map[string]hub.Bandwidth{}
	wgData, err := wg.client.Device(_interface)
	if err != nil {
		return clientsUsageMap, err
	}

	for _, peer := range wgData.Peers {
		pubkey := peer.PublicKey
		usage := hub.NewBandwidthFromInt64(peer.ReceiveBytes, peer.TransmitBytes)
		if peer.LastHandshakeTime.Minute() < 3 {
			clientsUsageMap[pubkey.String()] = usage
		} else {
			wg.DisconnectClient(pubkey.String())
		}
	}
	return clientsUsageMap, nil
}

// DisconnectClient ...
func (wg WireGuard) DisconnectClient(pubkey string) error {
	fmt.Print("\nDisconnecting client ...\n")
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
	err = wg.client.ConfigureDevice(_interface, cfg)
	if err != nil {
		log.Println("err:", err)
		return err
	}
	return nil
}

// RevokeClient ...
func (wg WireGuard) RevokeClient(id string) error {
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
