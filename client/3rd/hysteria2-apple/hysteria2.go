// Package main provides a CGo wrapper around the Hysteria2 client library
// for use in the iOS Network Extension.
//
// Build as a static C-archive (embedded in Hysteria2.xcframework):
//
//	CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
//	  go build -buildmode=c-archive -o libhysteria2_arm64.a .
//
// See build_ios.sh for the full build script.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef void (*libhysteria2_sockcallback)(uintptr_t fd, void* ctx);

static inline void callHysteria2SockCallback(libhysteria2_sockcallback cb, uintptr_t fd, void* ctx) {
    if (cb) cb(fd, ctx);
}
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"gopkg.in/yaml.v3"
)

// --- Global state ---

var (
	mu         sync.Mutex
	cancelFunc context.CancelFunc

	sockCbMu  sync.Mutex
	sockCb    C.libhysteria2_sockcallback
	sockCbCtx unsafe.Pointer
)

// --- C-exported API ---

// LibHysteria2SetSockCallback registers a callback invoked for every UDP socket
// created by Hysteria2. iOS uses this to bind sockets to the physical interface
// via IP_BOUND_IF / IPV6_BOUND_IF, preventing routing loops through the TUN.
//
//export LibHysteria2SetSockCallback
func LibHysteria2SetSockCallback(cb C.libhysteria2_sockcallback, ctx unsafe.Pointer) {
	sockCbMu.Lock()
	defer sockCbMu.Unlock()
	sockCb = cb
	sockCbCtx = ctx
}

// LibHysteria2RunClient reads a Hysteria2 YAML config from configPath, starts
// the client with an embedded SOCKS5 proxy (TCP CONNECT + UDP ASSOCIATE), and
// blocks until LibHysteria2StopClient is called.
//
//export LibHysteria2RunClient
func LibHysteria2RunClient(configPath *C.char) {
	mu.Lock()
	if cancelFunc != nil {
		cancelFunc()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancelFunc = cancel
	mu.Unlock()

	path := C.GoString(configPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var cfg clientYAML
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return
	}

	runClient(ctx, cfg)
}

// LibHysteria2StopClient stops the currently running Hysteria2 client.
//
//export LibHysteria2StopClient
func LibHysteria2StopClient() {
	mu.Lock()
	defer mu.Unlock()
	if cancelFunc != nil {
		cancelFunc()
		cancelFunc = nil
	}
}

// --- Config (mirrors the YAML written by Swift) ---

type clientYAML struct {
	Server    string `yaml:"server"`
	Auth      string `yaml:"auth"`
	Bandwidth struct {
		Up   string `yaml:"up"`
		Down string `yaml:"down"`
	} `yaml:"bandwidth"`
	TLS struct {
		SNI      string `yaml:"sni"`
		Insecure bool   `yaml:"insecure"`
	} `yaml:"tls"`
	Obfs struct {
		Type       string `yaml:"type"`
		Salamander struct {
			Password string `yaml:"password"`
		} `yaml:"salamander"`
	} `yaml:"obfs"`
	SOCKS5 struct {
		Listen string `yaml:"listen"`
	} `yaml:"socks5"`
}

// --- iOS socket protection ---

// iosSockControl returns a net.ListenConfig.Control function that fires the
// registered iOS callback for every newly created socket, so the Network
// Extension can bind it to the physical interface before any data is sent.
func iosSockControl(network, address string, c syscall.RawConn) error {
	sockCbMu.Lock()
	cb := sockCb
	ctx := sockCbCtx
	sockCbMu.Unlock()
	if cb == nil {
		return nil
	}
	return c.Control(func(fd uintptr) {
		C.callHysteria2SockCallback(cb, C.uintptr_t(fd), ctx)
	})
}

// iosConnFactory implements hyClient.ConnFactory with iOS socket protection
// and optional Salamander obfuscation.
type iosConnFactory struct {
	obfuscator obfs.Obfuscator
}

func (f *iosConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: iosSockControl}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	if f.obfuscator != nil {
		return obfs.WrapPacketConn(pc, f.obfuscator), nil
	}
	return pc, nil
}

// --- Client runner ---

func runClient(ctx context.Context, cfg clientYAML) {
	// Build optional obfuscator
	var obfuscator obfs.Obfuscator
	if cfg.Obfs.Type == "salamander" && cfg.Obfs.Salamander.Password != "" {
		o, err := obfs.NewSalamanderObfuscator([]byte(cfg.Obfs.Salamander.Password))
		if err == nil {
			obfuscator = o
		}
	}

	// Resolve server address (host:port → net.Addr)
	serverAddr, err := net.ResolveUDPAddr("udp", cfg.Server)
	if err != nil {
		return
	}

	hyCfg := &hyClient.Config{
		ConnFactory: &iosConnFactory{obfuscator: obfuscator},
		ServerAddr:  serverAddr,
		Auth:        cfg.Auth,
		TLSConfig: hyClient.TLSConfig{
			ServerName:         cfg.TLS.SNI,
			InsecureSkipVerify: cfg.TLS.Insecure,
		},
	}

	hystClient, err := hyClient.NewReconnectableClient(
		func() (*hyClient.Config, error) { return hyCfg, nil },
		func(_ hyClient.Client, _ *hyClient.HandshakeInfo, _ int) {},
		false,
	)
	if err != nil {
		return
	}
	defer hystClient.Close()

	listen := cfg.SOCKS5.Listen
	if listen == "" {
		listen = "[::1]:10808"
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return
	}
	defer ln.Close()

	go serveSocks5(ctx, ln, hystClient)
	<-ctx.Done()
}

// --- SOCKS5 server (TCP CONNECT + UDP ASSOCIATE) ---

const (
	socks5Ver          = 5
	cmdConnect         = 1
	cmdUDPAssoc        = 3
	atypIPv4           = 1
	atypDomain         = 3
	atypIPv6           = 4
	repSuccess         = 0
	repGenFail         = 1
	repHostUnreachable = 4
	repCmdNotSupported = 7
)

func serveSocks5(ctx context.Context, ln net.Listener, hc hyClient.Client) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handleSocks5(ctx, conn, hc)
	}
}

func handleSocks5(ctx context.Context, conn net.Conn, hc hyClient.Client) {
	defer conn.Close()

	// Auth negotiation
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != socks5Ver {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	conn.Write([]byte{socks5Ver, 0}) //nolint:errcheck — no-auth

	// Request
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != socks5Ver {
		return
	}
	target, err := readSocks5Addr(conn, req[3])
	if err != nil {
		socks5Reply(conn, repGenFail)
		return
	}

	switch req[1] {
	case cmdConnect:
		socks5Connect(conn, hc, target)
	case cmdUDPAssoc:
		socks5UDPAssoc(ctx, conn, hc)
	default:
		socks5Reply(conn, repCmdNotSupported)
	}
}

func readSocks5Addr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 6)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", buf[0], buf[1], buf[2], buf[3],
			binary.BigEndian.Uint16(buf[4:])), nil

	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", err
		}
		buf := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s:%d", buf[:len(buf)-2],
			binary.BigEndian.Uint16(buf[len(buf)-2:])), nil

	case atypIPv6:
		buf := make([]byte, 18)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return fmt.Sprintf("[%s]:%d", net.IP(buf[:16]).String(),
			binary.BigEndian.Uint16(buf[16:])), nil

	default:
		return "", fmt.Errorf("unsupported atyp: %d", atyp)
	}
}

func socks5Reply(conn net.Conn, code byte) {
	conn.Write([]byte{socks5Ver, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
}

func socks5Connect(conn net.Conn, hc hyClient.Client, target string) {
	remote, err := hc.TCP(target)
	if err != nil {
		socks5Reply(conn, repHostUnreachable)
		return
	}
	defer remote.Close()

	socks5Reply(conn, repSuccess)
	go io.Copy(remote, conn) //nolint:errcheck
	io.Copy(conn, remote)    //nolint:errcheck
}

// socks5UDPAssoc handles SOCKS5 UDP ASSOCIATE, required by hev-socks5-tunnel
// to relay DNS and UDP traffic from the TUN device.
func socks5UDPAssoc(ctx context.Context, conn net.Conn, hc hyClient.Client) {
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		socks5Reply(conn, repGenFail)
		return
	}
	defer pc.Close()

	hyUDP, err := hc.UDP()
	if err != nil {
		socks5Reply(conn, repGenFail)
		return
	}
	defer hyUDP.Close()

	la := pc.LocalAddr().(*net.UDPAddr)
	rep := make([]byte, 0, 22)
	rep = append(rep, socks5Ver, repSuccess, 0, atypIPv6)
	rep = append(rep, la.IP.To16()...)
	rep = append(rep, byte(la.Port>>8), byte(la.Port))
	conn.Write(rep) //nolint:errcheck

	var (
		caMu sync.Mutex
		ca   net.Addr
	)

	// Hysteria2 → SOCKS5 client
	go func() {
		for {
			data, addr, err := hyUDP.Receive()
			if err != nil {
				return
			}
			caMu.Lock()
			dst := ca
			caMu.Unlock()
			if dst == nil {
				continue
			}
			pc.WriteTo(append(buildUDPHeader(addr), data...), dst) //nolint:errcheck
		}
	}()

	// SOCKS5 client → Hysteria2
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			caMu.Lock()
			ca = from
			caMu.Unlock()
			payload, target, err := parseUDPPacket(buf[:n])
			if err != nil {
				continue
			}
			hyUDP.Send(payload, target) //nolint:errcheck
		}
	}()

	io.Copy(io.Discard, conn) //nolint:errcheck
}

func parseUDPPacket(data []byte) ([]byte, string, error) {
	if len(data) < 4 || data[2] != 0 {
		return nil, "", fmt.Errorf("invalid UDP packet")
	}
	r := bytes.NewReader(data[3:])
	atyp := make([]byte, 1)
	if _, err := r.Read(atyp); err != nil {
		return nil, "", err
	}
	addr, err := readSocks5Addr(r, atyp[0])
	if err != nil {
		return nil, "", err
	}
	payload, _ := io.ReadAll(r)
	return payload, addr, nil
}

func buildUDPHeader(addrStr string) []byte {
	host, portStr, _ := net.SplitHostPort(addrStr)
	port, _ := strconv.Atoi(portStr)
	var hdr []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			hdr = append([]byte{0, 0, 0, atypIPv4}, ip4...)
		} else {
			hdr = append([]byte{0, 0, 0, atypIPv6}, ip.To16()...)
		}
	} else {
		hdr = append([]byte{0, 0, 0, atypDomain, byte(len(host))}, []byte(host)...)
	}
	return append(hdr, byte(port>>8), byte(port))
}

func main() {}
