package wireguard

import (
  "fmt"
)

func cmdAddDevLink(_inteface, _type string) string {
  return fmt.Sprintf("ip link add dev %s type %s", _interface, _type)
}

func cmdDelDevLink(_interface string) string {
  return fmt.Sprintf("ip link del dev %s", _interface)
}

func cmdSetDevMTU(_interface string, mtu int) string {
  return fmt.Sprintf("ip link set mtu %d up dev %s", mtu, _interface)
}

func cmdAddDevAddressIPv4(addr, _interface string) string {
  return fmt.Sprintf("ip -4 address add %s dev %s", addr, _interface)
}

func cmdAddDevAdressIPv6(addr, _interface string) string {
  return fmt.Sprintf("ip -6 address add %s dev %s", addr, _interface)
}

func cmdSetNatRouting(_interface string) string {
  return fmt.Sprintf(`iptables -C FORWARD -i %s -j ACCEPT &&
  iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE && iptables -C FORWARD -o %s -j ACCEPT`,
  _interface, _interface)
}
