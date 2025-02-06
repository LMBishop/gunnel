package wireguard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

type Peer struct {
	IPAddr     net.IP
	PublicKey  string
	PrivateKey string
}

type Service interface {
	// GenerateKey() (string, error)
	Up(iface string, network string, listenPort string) (string, error)
	Down() error
	NewPeer() (*Peer, error)
	RemovePeer(peer *Peer) error
	PublicKey() string
}

type service struct {
	ipNet   *net.IPNet
	startIP uint32
	endIP   uint32
	nextIP  uint32

	iface      string
	privateKey string
	publicKey  string
}

func NewService() Service {
	return &service{}
}

func (s *service) Up(iface string, network string, listenPort string) (string, error) {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return "", fmt.Errorf("cannot parse CIDR: %w", err)
	}

	s.ipNet = ipNet
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	s.startIP = binary.BigEndian.Uint32(ipNet.IP)
	s.endIP = (s.startIP & mask) | (mask ^ 0xffffffff)
	s.nextIP = s.startIP

	private, err := s.generateKey()
	if err != nil {
		return "", fmt.Errorf("cannot generate private key: %w", err)
	}
	public, err := s.getPublicKey(private)
	if err != nil {
		return "", fmt.Errorf("cannot get public key: %w", err)
	}

	fd, err := memfile("wg", []byte(private))

	addInterface := fmt.Sprintf("ip link add dev %s type wireguard", iface)
	addAddress := fmt.Sprintf("ip addr add %s dev %s", network, iface)
	setPrivateKey := fmt.Sprintf("wg set %s private-key /dev/fd/%d listen-port %s", iface, fd, listenPort)
	ifaceUp := fmt.Sprintf("ip link set %s up", iface)

	cmd := exec.Command("bash", "-c", fmt.Sprintf("%s; %s; %s; %s", addInterface, addAddress, setPrivateKey, ifaceUp))
	_, err = cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cannot bring WireGuard interface up: %w", err)
	}

	s.iface = iface
	s.privateKey = private
	s.publicKey = public

	return public, nil
}

func (s *service) Down() error {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("ip link delete dev %s", s.iface))
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("cannot bring WireGuard interface down: %w", err)
	}
	return nil
}

func (s *service) NewPeer() (*Peer, error) {
	private, err := s.generateKey()
	if err != nil {
		return nil, fmt.Errorf("cannot generate private key: %w", err)
	}
	public, err := s.getPublicKey(private)
	if err != nil {
		return nil, fmt.Errorf("cannot get public key: %w", err)
	}

	ipAddress, err := s.getNextIP()
	if err != nil {
		return nil, fmt.Errorf("could not assign new IP: %w", err)
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf("wg set %s peer %s allowed-ips %s/32", s.iface, public, ipAddress.String()))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cannot add peer: %s: %w", string(output), err)
	}

	return &Peer{
		IPAddr:     ipAddress,
		PrivateKey: private,
		PublicKey:  public,
	}, nil
}

func (s *service) RemovePeer(peer *Peer) error {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("wg set %s peer %s remove", s.iface, peer.PublicKey))
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("cannot remove peer: %w", err)
	}
	return nil
}

func (s *service) PublicKey() string {
	return s.publicKey
}

func (s *service) getNextIP() (net.IP, error) {
	for {
		if s.nextIP == s.endIP {
			return net.IP{}, fmt.Errorf("no more IP addresses remaining")
		}

		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, s.nextIP)

		if ip[3] != 0 && ip[3] != 255 {
			s.nextIP++
			return ip, nil
		}

		s.nextIP++
	}
}

func (s *service) generateKey() (string, error) {
	cmd := exec.Command("wg", "genkey")
	stdout, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.Replace(string(stdout[:]), "\n", "", -1), nil
}

func (s *service) getPublicKey(private string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = bytes.NewBufferString(private)
	stdout, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.Replace(string(stdout[:]), "\n", "", -1), nil
}

func memfile(name string, b []byte) (int, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return 0, fmt.Errorf("MemfdCreate: %v", err)
	}

	err = unix.Ftruncate(fd, int64(len(b)))
	if err != nil {
		return 0, fmt.Errorf("Ftruncate: %v", err)
	}

	data, err := unix.Mmap(fd, 0, len(b), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, fmt.Errorf("Mmap: %v", err)
	}

	copy(data, b)

	err = unix.Munmap(data)
	if err != nil {
		return 0, fmt.Errorf("Munmap: %v", err)
	}

	return fd, nil
}
