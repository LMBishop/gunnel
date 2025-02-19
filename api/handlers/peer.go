package handlers

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/LMBishop/gunnel/pkg/config"
	"github.com/LMBishop/gunnel/pkg/store"
	"github.com/LMBishop/gunnel/pkg/wireguard"
	"github.com/gorilla/mux"
)

const script = `#!/bin/bash

# Your IP address: %s
# Private key: %s
# Unique slug: %s

# Run this script as root to set up your client

set -euo pipefail

sudo ip link delete dev %s 2>/dev/null || true
sudo ip link add %s type wireguard
sudo ip addr add %s dev %s
echo "%s" | sudo tee /tmp/tunnel-private > /dev/null
sudo wg set %s private-key /tmp/tunnel-private
sudo wg set %s peer %s allowed-ips %s endpoint %s:%s persistent-keepalive 21
sudo ip link set up dev %s
sudo ip route add %s dev %s

echo "http://0.0.0.0:%s is now reachable at http://%s.%s"`

func NewPeer(storeService store.Service, wireguardService wireguard.Service, configService config.Service) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		port := params["port"]
		key := r.URL.Query().Get("key")

		if configService.Config().Permissions.Enabled {
			if subtle.ConstantTimeCompare([]byte(key), []byte(configService.Config().Permissions.SecretKey)) != 1 {
				http.Error(w, "bad key", http.StatusForbidden)
			}
		}

		peer, err := wireguardService.NewPeer()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slug := storeService.GetUnusedSlug()

		ipAddr := peer.IPAddr.String()

		storeService.NewForwardingRule(slug, peer, port)

		iface := configService.Config().WireGuard.InterfaceName
		wireguardPort := configService.Config().WireGuard.Port
		hostname := configService.Config().Hostname
		network := configService.Config().WireGuard.Network
		publicKey := wireguardService.PublicKey()

		slog.Info("new peer", "peer", peer.PrivateKey)

		fmt.Fprintf(w, script,
			ipAddr,
			peer.PrivateKey,
			slug,
			iface,
			iface,
			ipAddr, iface,
			peer.PrivateKey,
			iface,
			iface, publicKey, network, hostname, wireguardPort,
			iface,
			network, iface,
			port, slug, hostname,
		)
	}
}
