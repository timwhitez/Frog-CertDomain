package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args)<3{
		fmt.Println(usage)
		return
	}
	host:=os.Args[1]
	port:=os.Args[2]
	CN, DN, err:= Execute(host,port,10*time.Second)
	if err != nil{
		return
	}
	fmt.Print("CommonName: "+CN+"; ")

	for i := 0; i < len(DN); i++ {
		fmt.Print("DNSName: " + DN[i] + "; ")
	}
}

const usage = `Usage of certinfo

    certinfo.exe <host> <port>

`


func hostsFrom(ss []string) []string {
	for i, s := range ss {
		u, _ := url.Parse(s)
		if host := u.Hostname(); host != "" {
			ss[i] = host
		}
	}
	return ss
}

type hostinfo struct {
	Host  string
	Port  int
	Certs []*x509.Certificate
}

func (h *hostinfo) getCerts(timeout time.Duration) error {
	//log.Printf("connecting to %s:%d", h.Host, h.Port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		h.Host+":"+strconv.Itoa(h.Port),
		&tls.Config{
			InsecureSkipVerify: true,
		})
	if err != nil {
		return err
	}

	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return err
	}

	pc := conn.ConnectionState().PeerCertificates
	h.Certs = make([]*x509.Certificate, 0, len(pc))
	for _, cert := range pc {
		if cert.IsCA {
			continue
		}
		h.Certs = append(h.Certs, cert)
	}

	return nil
}

func Execute(host string, port string, timeout time.Duration) (commonName string, dnsNames []string, err error) {
	port_int,err := strconv.Atoi(port)
	if err != nil{
		return commonName, dnsNames, err
	}
	info := hostinfo{Host: host, Port: port_int}
	err = info.getCerts(timeout)
	if err != nil {
		return commonName, dnsNames, err
	}
	for _, cert := range info.Certs {
		if cert != nil && cert.Subject.CommonName != "" {
			return cert.Subject.CommonName, cert.DNSNames, err
		}
	}
	return commonName, dnsNames, errors.New("not found")
}
