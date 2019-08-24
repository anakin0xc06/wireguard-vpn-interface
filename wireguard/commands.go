package wireguard

import (
  "fmt"
  "os/exec"
)

func cmdAddDevLink(_inteface, _type string) string {
  return exec.Command("sh", "-c", fmt.Sprintf("ip link add dev %s type %s", _interface, _type)
}

func cmdDeleteDevLink(_interface string) string {
  return exec.Command("sh", "-c", fmt.Sprintf("ip link del dev %s", _interface)
}

func cmdSetDevMTU(_interface string, mtu int) string {
  return exec.Command("sh", "-c", fmt.Sprintf("ip link set mtu %d up dev %s", mtu, _interface)
}

func cmdAddDevAddressIPv4(_interface, addr string) string {
  return exec.Command("sh", "-c", fmt.Sprintf("ip -4 address add %s dev %s", addr, _interface)
}

func cmdAddDevAdressIPv6(_interface, addr string) string {
  return exec.Command("sh", "-c", fmt.Sprintf("ip -6 address add %s dev %s", addr, _interface)
}

func cmdSetNatRouting(_interface string) string {
  return exec.Command("sh", "-c", fmt.Sprintf(`iptables -C FORWARD -i %s -j ACCEPT &&
  iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE && iptables -C FORWARD -o %s -j ACCEPT`,
  _interface, _interface)
}
