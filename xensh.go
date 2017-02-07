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

	infoblox "github.com/fanatic/go-infoblox"
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

	delvm     = app.Command("delvm", "Destroy vm - really fast ")
	delvmName = delvm.Arg("vm address", "Address of the VM to find").Required().String()
	delHyp    = delvm.Arg("hyp address", "Address of hypervisor where delete the machine").Required().String()

	searchdel = app.Command("searchdel", "Search and Destroy vm - really fast ")
	sdvmName  = searchdel.Arg("vm address", "Address of the VM to find").Required().String()

	delhost  = app.Command("delhost", "Removing all records from Infoblox - not that fast")
	ibvmName = delhost.Arg("host name", "Name of the host/vm").Required().String()
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

	fmt.Println("Resolving hypervisors ... \n")
	IPs := make([]*net.IPAddr, scope+1)
	sem := make(chan empty, scope+1)

	for i := 0; i < scope; i++ {
		hyp := fmt.Sprintf("hyp%d.%s.%s.%s", i+1, pod, dc, domain)
		go func(i int) {
			defer wg.Done()

			ip, err := net.ResolveIPAddr("ip4:icmp", hyp)
			if err == nil {
				IPs[i+1] = ip
			}
			// suppress output
			//	else {
			// fmt.Println(err)
			//	}
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
		fmt.Println("NS Lookup finished, going to ping ... \n")
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
		lpass := getCreds(".xensh.json")
		login, pass = lpass.Login, lpass.Password
	}

	x := NewXenAPIClient(hyp, login, pass)
	x.Login()

	return x

}

func readCreds() (login string, pass string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("[XEN] Enter Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("[XEN] Enter Password: ")
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

func getCreds(config_name string) (c Creds) {
	usr, err := user.Current()
	if err != nil {
		panic("panic")
	}
	config := string(usr.HomeDir) + "/" + config_name
	raw, err := ioutil.ReadFile(config)
	json.Unmarshal(raw, &c)
	return c
}

func parseVMName(vmname string) (pod, dc, domain string) {
	vm := strings.Split(vmname, ".")
	domain = strings.Join([]string{vm[3], vm[4]}, ".")
	return vm[1], vm[2], domain
}

func scanSingleVM(IPAddr, vmname string) (hyp, name string, err error) {
	fmt.Printf("Scanning VM in HYP %+v\n", IPAddr)
	xclient := XenAuth(IPAddr)
	vms, _ := xclient.GetVMByNameLabel(vmname)
	if len(vms) > 0 {
		for _, a := range vms {
			name, _ = a.GetUuid()
			foundhyp, _ := net.LookupAddr(IPAddr)
			fmt.Printf("\n>>> VM found name = %+v, uid = %+v \n>>> at hyp = %+v \n", vmname, name, foundhyp[0])
			hyp = foundhyp[0]
		}
		return hyp, name, nil
	}
	return "not found", "not found", fmt.Errorf("didn't find a machine on this hyp")
}

func scanVM(PingableIPs []*net.IPAddr, vmname string) (hyp string) {
	var wg sync.WaitGroup

	length := len(PingableIPs)

	wg.Add(length)
	sem := make(chan empty, length)

	var name string
	var err error

	for _, IPAddr := range PingableIPs {
		go func(IPAddr *net.IPAddr) {
			defer wg.Done()
			hyp, name, err = scanSingleVM(fmt.Sprintf("%v", IPAddr), vmname)
			sem <- empty{}
		}(IPAddr)
	}

	for i := 0; i < length; i++ {
		<-sem
	}

	return hyp
}

func destroyVM(vmname, hyp string) {
	xclient := XenAuth(hyp)
	vms, _ := xclient.GetVMByNameLabel(vmname)
	if len(vms) > 1 {
		panic("More than one machine with the same label I don't want to delete it")
	}
	for _, a := range vms {
		fmt.Printf("\nDestroy VM = %+v\n", a)
		if os.Getenv("DRY") == "false" {
			fmt.Printf("\nWe are destroying VM, like for real %+v\n", a)
			fmt.Println("Shutting down ..")
			err := a.HardShutdown()
			if err != nil {
				panic(err)
			}
			fmt.Println("Destroying ...")
			err = a.Destroy()
			if err != nil {
				panic(err)
			}
			fmt.Println("Have a good day, destroyer!")
		}
	}
}

func AuthInfoblox() *infoblox.Client {

	var login, pass string

	usr, _ := user.Current()
	// not recommended to have this file in place for real life
	config := string(usr.HomeDir) + "/.infoblox.json"
	if _, err := os.Stat(config); os.IsNotExist(err) {
		if err != nil {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("[INFOBLOX] Enter Username: ")
			username, _ := reader.ReadString('\n')

			fmt.Print("[INFOBLOX] Enter Password: ")
			bytePassword, err := terminal.ReadPassword(0)
			if err != nil {
				panic("Can not read password")
			}

			login = strings.TrimSpace(username)
			pass = strings.TrimSpace(string(bytePassword))
		}
	} else {
		lpass := getCreds(".infoblox.json")
		login, pass = lpass.Login, lpass.Password
	}

	ib := infoblox.NewClient("https://ddi.zdsys.com", login, pass, false, false)

	return ib
}

func DelInfobloxRecords(hostname string, ib *infoblox.Client) {

	out, _ := ib.FindRecordHost(hostname)
	fmt.Printf("out = %+v\n", out)
	host_object := out[0].Object
	fmt.Printf("Host object to remove %+v\n", host_object.Ref)
	ip := fmt.Sprintf("%v", out[0].Ipv4Addrs[0].Ipv4Addr)

	var err error

	if os.Getenv("DRY") == "false" {
		//err := host_object.Delete(nil)
		err = ib.RecordHostObject(host_object.Ref).Delete(nil)
		if err != nil {
			fmt.Println(err)
		}
	}

	fmt.Printf("Host record to remove %s\n", ip)

	ip_obj, _ := ib.FindIP(ip)
	fmt.Printf("Fixed IP object to remove %+v\n", ip_obj[0].Object.Ref)

	if os.Getenv("DRY") == "false" {
		err = ib.Ipv4addressObject(ip_obj[0].Object.Ref).Delete(nil)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func printList(out []map[string]interface{}, err error) {
	e(err)
	for i, v := range out {
		fmt.Printf("[%d]\n", i)
		printObject(v, nil)
	}
}

func printObject(out map[string]interface{}, err error) {
	e(err)
	for k, v := range out {
		fmt.Printf("  %s: %q\n", k, v)
	}
	fmt.Printf("\n")
}

func e(err error) {
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func main() {

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case findvm.FullCommand():
		// SCOPE Should be configurable ?
		scope := 20
		pod, dc, domain := parseVMName(*vmName)

		PingableIPs := ping_hypervisors(domain, dc, pod, scope)
		if len(clear_slice(PingableIPs)) == 0 {
			panic("No pingable IPs found, this app requires SUDO to ping and are you connected to VPN ?")
		}
		scanVM(PingableIPs, *vmName)
	case delvm.FullCommand():
		destroyVM(*delvmName, *delHyp)
	case searchdel.FullCommand():

		scope := 20
		pod, dc, domain := parseVMName(*sdvmName)

		PingableIPs := ping_hypervisors(domain, dc, pod, scope)
		if len(clear_slice(PingableIPs)) == 0 {
			panic("No pingable IPs found, are on VPN ?")
		}
		hyp := scanVM(PingableIPs, *sdvmName)
		destroyVM(*sdvmName, hyp)

	case delhost.FullCommand():
		ib := AuthInfoblox()
		DelInfobloxRecords(*ibvmName, ib)

	}

}
