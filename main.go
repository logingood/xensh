package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/nilshell/xmlrpc"
	"github.com/tatsushid/go-fastping"
	xsclient "github.com/xenserver/go-xenserver-client"
	//"gopkg.in/yaml.v2"
	//		"gopkg.in/alecthomas/kingpin.v2"
)

type XenAPIClient struct {
	xsclient.XenAPIClient
}

type Config struct {
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
	DCs      []DC
}

type DC struct {
	Name string `yaml:"name"`
	Pods []int  `yaml:"pods"`
}

func NewXenAPIClient(host, username, password string) (c XenAPIClient) {
	c.Host = host
	c.Url = "https://" + host
	c.Username = username
	c.Password = password
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	c.RPC, _ = xmlrpc.NewClient(c.Url, tr)
	return
}

func (client *XenAPIClient) Login() (err error) {
	//Do loging call
	result := xmlrpc.Struct{}

	params := make([]interface{}, 2)
	params[0] = client.Username
	params[1] = client.Password

	err = client.RPCCall(&result, "session.login_with_password", params)
	client.Session = result["Value"]
	return err
}

type empty struct{}

func clear_slice(slice []*net.IPAddr) []*net.IPAddr {
	var r []*net.IPAddr
	for _, ip := range slice {
		if ip != nil {
			r = append(r, ip)
		}
	}
	return r
}

func scan_ns_hypervisors(domain, dc string, pod, scope int) []*net.IPAddr {
	var wg sync.WaitGroup
	wg.Add(scope)

	fmt.Println("Resolving hypervisors in parrallel\n")

	IPs := make([]*net.IPAddr, scope)
	sem := make(chan empty, scope)

	for i := 1; i < scope; i++ {
		hyp := fmt.Sprintf("hyp%d.pod%d.%s.%s", i, pod, dc, domain)
		go func(i int) {
			defer wg.Done()

			ip, err := net.ResolveIPAddr("ip4:icmp", hyp)
			if err == nil {
				IPs[i+1] = ip
			} else {
				fmt.Println(err)
			}
			sem <- empty{}
		}(i)
	}
	for i := 1; i < scope; i++ {
		<-sem
	}
	IPs = clear_slice(IPs)
	return IPs
}

func ping_hypervisors(domain, dc string, pod, scope int) []*net.IPAddr {

	p := fastping.NewPinger()
	ras := scan_ns_hypervisors(domain, dc, pod, scope)

	for i := 0; i < len(ras); i++ {
		p.AddIPAddr(ras[i])
	}

	PingableIPs := make([]*net.IPAddr, len(ras))

	k := 0

	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		PingableIPs[k] = addr
		k = k + 1
	}

	p.OnIdle = func() {
		fmt.Println("finish")
	}
	err := p.Run()

	if err != nil {
		fmt.Println(err)
	}
	return PingableIPs
}

func main() {

	runtime.GOMAXPROCS(4)

	domain := "zdsys.com"
	pod := 3
	dc := "dub1"
	scope := 20

	PingableIPs := ping_hypervisors(domain, dc, pod, scope)

	fmt.Println("%+v", PingableIPs)

	c := NewXenAPIClient("hyp1.pod2.sac1.zdsys.com", "root", "989mark3t")
	c.Login()
	name_label := "zoo1.pod2.sac1.zdsys.com"
	vms, _ := c.GetVMByNameLabel(name_label)
	for _, a := range vms {
		name, _ := a.GetUuid()
		fmt.Printf("VM uid = %+v", name)
	}
}
