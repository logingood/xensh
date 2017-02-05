package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	//"os/exec"
	"bufio"
	"encoding/json"
	"io/ioutil"
	"os/user"
	"runtime"
	"sync"
	"time"

	"github.com/nilshell/xmlrpc"
	"github.com/tatsushid/go-fastping"
	xsclient "github.com/xenserver/go-xenserver-client"
	"golang.org/x/crypto/ssh/terminal"
	//"gopkg.in/yaml.v2"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("xensh", "A command-line xen tool")

	findvm = app.Command("findvm", "Find vm - really fast ")
	vmName = findvm.Arg("vm address", "Address of the VM to find").Required().String()
)

type XenAPIClient struct {
	xsclient.XenAPIClient
}

type Creds struct {
	Login    string `json:"login"`
	Password string `json:"password"`
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

func scan_ns_hypervisors(domain, dc, pod string, scope int) []*net.IPAddr {
	runtime.GOMAXPROCS(4)
	var wg sync.WaitGroup
	wg.Add(scope)

	fmt.Println("Resolving hypervisors in parrallel\n")
	IPs := make([]*net.IPAddr, scope+1)
	sem := make(chan empty, scope+1)

	for i := 0; i < scope; i++ {
		hyp := fmt.Sprintf("hyp%d.%s.%s.%s", i+1, pod, dc, domain)
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
	for i := 0; i < scope; i++ {
		<-sem
	}
	IPs = clear_slice(IPs)
	return IPs
}

func ping_hypervisors(domain, dc, pod string, scope int) []*net.IPAddr {
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
		fmt.Println(" NS Lookup finished, going to ping")
	}
	err := p.Run()
	if err != nil {
		fmt.Println(err)
	}
	return PingableIPs
}

func read_config() {

}

func XenAuth(hyp string) XenAPIClient {
	usr, _ := user.Current()
	config := string(usr.HomeDir) + "/.xensh.json"
	var login, pass string
	if _, err := os.Stat(config); os.IsNotExist(err) {
		if err != nil {
			login, pass = writeCreds()
		}
	} else {
		lpass := getCreds()
		login, pass = lpass.Login, lpass.Password
	}

	x := NewXenAPIClient(hyp, login, pass)
	x.Login()

	return x

}

func readCreds() (login string, pass string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(0)
	if err != nil {
		panic("Can not read password")
	}

	login = strings.TrimSpace(username)
	pass = strings.TrimSpace(string(bytePassword))

	return login, pass
}

func writeCreds() (login, pass string) {
	login, pass = readCreds()
	creds := Creds{login, pass}
	b, err := json.Marshal(creds)

	usr, err := user.Current()
	if err != nil {
		panic("panic")
	}

	config := string(usr.HomeDir) + "/.xensh.json"
	err = ioutil.WriteFile(config, b, 0600)

	return login, pass
}

func getCreds() (c Creds) {
	usr, err := user.Current()
	if err != nil {
		panic("panic")
	}
	config := string(usr.HomeDir) + "/.xensh.json"
	raw, err := ioutil.ReadFile(config)
	json.Unmarshal(raw, &c)
	return c
}

func parseVMName(vmname string) (pod, dc, domain string) {
	vm := strings.Split(vmname, ".")
	domain = strings.Join([]string{vm[3], vm[4]}, ".")
	return vm[1], vm[2], domain
}

func main() {

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case findvm.FullCommand():
		// SCOPE Should be configurable ?
		scope := 20

		pod, dc, domain := parseVMName(*vmName)

		PingableIPs := ping_hypervisors(domain, dc, pod, scope)
		if len(clear_slice(PingableIPs)) == 0 {
			panic("No pingable IPs found, are on VPN ?")
		}

		var wg sync.WaitGroup
		wg.Add(len(PingableIPs) + 1)
		sem := make(chan empty, len(PingableIPs)+1)
		var name, hypip string

		for _, IPAddr := range PingableIPs {
			go func(IPAddr *net.IPAddr) {
				defer wg.Done()
				fmt.Printf("Scanning VM in HYP %+v\n", IPAddr)
				xclient := XenAuth(fmt.Sprintf("%+v", IPAddr))
				vms, _ := xclient.GetVMByNameLabel(*vmName)
				for _, a := range vms {
					name, _ = a.GetUuid()
					hypip = fmt.Sprintf("%+v", IPAddr)
					foundhyp, _ := net.LookupAddr(fmt.Sprintf("%v", hypip))
					fmt.Printf(">>> VM found uid = %+v \n at hyp = %+v \n", name, foundhyp[0])
					os.Exit(0)
				}
				sem <- empty{}
			}(IPAddr)
		}
		for i := 0; i < len(PingableIPs)+1; i++ {
			<-sem
		}
	}
}
