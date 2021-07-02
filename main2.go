package main
// Copy right wudifengz@2021
import (
	"flag"
	"fmt"
	"time"
)


func reSort(r scanRes) scanResr {
	n := scanResr{}
	for k, v := range r {
		for _, x := range v {
			if !inString(k, n[x]) {
				n[x] = append(n[x], k)
			}
		}
	}
	return n
}
func main() {
	iprang := flag.String("r", "", "ip range to scan.CIDR string like '192.168.0.2/24'.")
	ipaddr := flag.String("h", "", "ip address. each part of ip can be a range,like 1-2.3-4.5-6.7-8 . multi ip using ',' to split.")
	ports := flag.String("p", "", "Ports want to scan.multi port using ',' to split. range use '-', like 21,22,80-8000 .")
	renew := flag.Int("t", 20, "Seconds between 2 rescan.")
	lport := flag.Int("l", 8888, "HTTP Server port. ")
	acipl := flag.String("a", "", "IP range to accent to connect to the HTTP Server. ")
	flag.Parse()
	if (*iprang == "" && *ipaddr == "") || *ports == "" {
		fmt.Println("IP range or IP address and Ports must be set. -h see help")
		return
	}
	if *iprang != "" && *ipaddr != "" {
		fmt.Println("IP range and IP address can't been set at the same time.")
		return
	}
	rs := make(chan scanRes)
	hrs := make(chan scanRes)
	hrr := make(chan scanResr)
	ch := make(chan string)
	var r scanRes
	t := time.Tick(time.Second * 5)
	defer close(rs)
	defer close(ch)

	portlist := ParserPort(*ports)
	var iplist []string
	if *iprang != "" {
		iplist = getIPlist(*iprang)
		if iplist == nil {
			fmt.Println("[ERROR] Wrong CDIR string.")
			return
		}
	}
	if *ipaddr != "" {
		iplist = ParserIP(*ipaddr)
	}
	acl := ParserIP(*acipl)
	go StartServer(acl, hrs, hrr, *lport)
	go ScanIPs(iplist, portlist, *renew, rs, ch)
	for {
		select {
		case <-t:
			ch <- "get"
		case r = <-rs:
			hrs <- r
			hrr <- reSort(r)
		}
	}

}
