package wireguard

var (
  serverConfigTemplate = `[Interface]
Address = %s
ListenPort = %s
PrivateKey = %s`
  peerTemplate = `
[Peer]
PublicKey = %s
AllowedIps = %s`
  clientConfTemplate = `[Interface]
PrivateKey = %s
Address = %s/24
	
[Peer]
PublicKey = %s
EndPoint = %s
AllowedIPs=0.0.0.0/0, ::0/0`	
)
