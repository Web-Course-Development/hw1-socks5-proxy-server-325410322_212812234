package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
   "encoding/binary"

)
func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func negotiateAuth(conn net.Conn) (byte, error) {

	header := make([]byte, 2)

	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}

	version := header[0]
	nMethods := header[1]

	if version != 0x05 {
		return 0, fmt.Errorf("unsupported version")
	}

	methods := make([]byte, nMethods)

	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	requiredMethod := byte(0x00)

	if os.Getenv("PROXY_USER") != "" {
		requiredMethod = 0x02
	}

	found := false

	for _, m := range methods {
		if m == requiredMethod {
			found = true
			break
		}
	}

	if !found {
		conn.Write([]byte{0x05, 0xFF})
		return 0xFF, fmt.Errorf("no acceptable method")
	}

	conn.Write([]byte{0x05, requiredMethod})

	return requiredMethod, nil
}
func authenticateUserPass(conn net.Conn) error {

	// قراءة VER
	buf := make([]byte, 2)

	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid auth version")
	}

	ulen := int(buf[1])

	username := make([]byte, ulen)

	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	plenBuf := make([]byte, 1)

	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}

	plen := int(plenBuf[0])

	password := make([]byte, plen)

	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(username) == expectedUser &&
		string(password) == expectedPass {

		conn.Write([]byte{0x01, 0x00})
		return nil
	}

	conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("authentication failed")
}
func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		return
	}

	if method == 0x02 {
		if err := authenticateUserPass(conn); err != nil {
			return
		}
	}

	targetConn, err := handleConnect(conn)
	if err != nil {
		sendReply(conn, 0x05)
		return
	}
	defer targetConn.Close()

	sendReply(conn, 0x00)

	relay(conn, targetConn)
}
func handleConnect(conn net.Conn) (net.Conn, error) {

	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	ver := header[0]
	cmd := header[1]
	atyp := header[3]

	if ver != 0x05 {
		return nil, fmt.Errorf("invalid version")
	}

	if cmd != 0x01 {
		return nil, fmt.Errorf("command not supported")
	}

	var host string

	switch atyp {

	case 0x01: // IPv4

		ip := make([]byte, 4)

		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}

		host = net.IP(ip).String()

	case 0x03: // Domain

		lenBuf := make([]byte, 1)

		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}

		domainLen := int(lenBuf[0])

		domain := make([]byte, domainLen)

		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}

		host = string(domain)

	default:
		return nil, fmt.Errorf("address type not supported")
	}

	portBuf := make([]byte, 2)

	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}

	port := binary.BigEndian.Uint16(portBuf)

	address := fmt.Sprintf("%s:%d", host, port)

	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	return targetConn, nil
}
func sendReply(conn net.Conn, rep byte) error {

	reply := make([]byte, 10)

	reply[0] = 0x05
	reply[1] = rep
	reply[2] = 0x00
	reply[3] = 0x01

	_, err := conn.Write(reply)
	return err
}
func relay(client net.Conn, target net.Conn) {

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(target, client)

		if tcp, ok := target.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}

		done <- struct{}{}
	}()

	go func() {
		io.Copy(client, target)

		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}

		done <- struct{}{}
	}()

	<-done
	<-done
}