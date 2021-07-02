package main
// 解析器，用来解析运行时传入的参数
// parser to pars the arguments when the program start.
// Copy right wudifengz@2021
import (
	"net"
	"strconv"
	"strings"
)

// ip地址对象自增1
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

//获取CDIR规范的ip地址列表
func getIPlist(ipr string) []string {
	var ipl []string
	ipad, ipnt, err := net.ParseCIDR(ipr)
	if err != nil {
		return nil
	}
	for ip := ipad.Mask(ipnt.Mask); ipnt.Contains(ip); inc(ip) {
		ipl = append(ipl, ip.String())
	}
	return ipl
}

//解析 ports 参数。
//先使用 ”，“来划分端口组，再通过”-“区分首尾.
func ParserPort(ports string) []int {
	var ptl []int
	lports := strings.Split(ports, ",")
	for _, x := range lports {
		if strings.Contains(x, "-") {
			s, err := strconv.Atoi(strings.Split(x, "-")[0])
			if err != nil {
				continue
			}
			e, err := strconv.Atoi(strings.Split(x, "-")[1])
			if err != nil {
				continue
			}
			if s < 0 || e < 0 || s > 65535 || e > 65535 {
				continue
			}
			if s <= e {
				for ; s <= e; s++ {
					ptl = append(ptl, s)
				}
			} else {
				for ; e <= s; e++ {
					ptl = append(ptl, e)
				}
			}
		} else {
			s, err := strconv.Atoi(x)
			if err != nil {
				continue
			}
			ptl = append(ptl, s)

		}
	}
	return ptl
}

//解析 IP 参数。
func ParserIP(ips string) []string {
	var ipl []string
	if ips == "" {
		return ipl
	}
	ipr := strings.Split(ips, ",")
	for _, xip := range ipr {
		var ipp [4][]string
		bdip := false
		lip := strings.Split(xip, ".")
		if len(lip) != 4 {
			bdip = true
			continue
		}
		for i := 0; i < 4; i++ {
			x := lip[i]
			if strings.Contains(x, "-") {
				s, err := strconv.Atoi(strings.Split(x, "-")[0])
				if err != nil {
					bdip = true
					continue
				}
				e, err := strconv.Atoi(strings.Split(x, "-")[1])
				if err != nil {
					bdip = true
					continue
				}
				if s < 0 || e < 0 || s > 255 || e > 255 {
					bdip = true
					continue
				}
				if s <= e {
					for ; s <= e; s++ {
						ipp[i] = append(ipp[i], strconv.Itoa(s))
					}
				} else {
					for ; e <= s; e++ {
						ipp[i] = append(ipp[i], strconv.Itoa(e))
					}
				}
			} else {
				s, err := strconv.Atoi(x)
				if err != nil {
					bdip = true
					continue
				}
				if s < 0 || s > 255 {
					bdip = true
					continue
				}
				ipp[i] = append(ipp[i], strconv.Itoa(s))
			}
		}
		if bdip {
			continue
		}
		for _, a := range ipp[0] {
			for _, b := range ipp[1] {
				for _, c := range ipp[2] {
					for _, d := range ipp[3] {
						ipl = append(ipl, a+"."+b+"."+c+"."+d)
					}
				}
			}
		}
	}
	return ipl
}
