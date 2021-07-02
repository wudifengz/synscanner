package main
// 扫描主文件，包含任务发布函数、发射器、接收器
// main scanner file, include issue function, sander and receiver.
// Copy right wudifengz@2021
import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type job struct {
	host string
	port int
	stop bool
}
type popen struct {
	host   string
	port   int
	status bool
}
type scanRes = map[string][]int
type scanResr = map[int][]string

//判断 string 是否在 []string 中。
// To check whether the string object [a] is in string object list [b].
func inString(a string, b []string) bool {
	if len(b)==0{
		return false
	}
	lb := len(b) - 1
	mid := len(b) / 2
	if !sort.StringsAreSorted(b) {
		sort.Strings(b)
	}
	switch {
	case a == b[mid]:
		return true
	case a <= b[mid] && a >= b[0]:
		return inString(a, b[:mid])
	case a >= b[mid] && a <= b[lb]:
		return inString(a, b[mid+1:])
	default:
		return false
	}
}

//判断 int 是否在 []int 中。
// To check whether the int object [a] is in int object list [b].
func inInt(a int, b []int) bool {
	if len(b)==0{
		return false
	}
	lb := len(b) - 1
	mid := len(b) / 2
	if !sort.IntsAreSorted(b) {
		sort.Ints(b)
	}
	switch {
	case a == b[mid]:
		return true
	case a <= b[mid] && a >= b[0]:
		return inInt(a, b[:mid])
	case a >= b[mid] && a <= b[lb]:
		return inInt(a, b[mid+1:])
	default:
		return false
	}
}

//发送SYN包到指定IP地址的端口；通过job chan获取工作信息；deadline设置销毁周期，单位分钟,3倍周期后销毁发送器。
// send the SYN package to the target, target get form job chan.
func sender(jb <-chan job, deadline int) {
	i := 0
	for {
		select {
		case j := <-jb:
			i = 0
			_ = SendSyn(j.host, j.port)
		case <-time.Tick(time.Minute * time.Duration(deadline)):
			if i == 3 {
				return
			}
			i++
		}
	}
}

// 发布工作通过 [iplist] 获取IP列表，通过 [portlist] 获取端口列表，任务发布到 job chan 里
// sand the job into [job chan], IP from [iplist] list,port from [portlist] list.
func sendjob(iplist []string, portlist []int, jb chan<- job) {
	for i := 0; i < len(iplist); i++ {
		for j := 0; j < len(portlist); j++ {
			jb <- job{iplist[i], portlist[j], false}
		}
	}
}

// 扫描主函数，扫描 [iplist] 里所有主机是否开放 [portlist] 里的端口。
// main scan function.scan each host in [iplist] list and each port in [portlist] list.
func ScanIPs(iplist []string, portlist []int, rescan int, res chan<- scanRes, st <-chan string) {
	if len(iplist) == 0 || len(portlist) == 0 {
		fmt.Println("[Error] Wrong IP address list or port list .")
		return
	}
	jb := make(chan job, 5000)
	rs := make(chan popen, 300)
	t := time.Tick(time.Second * time.Duration(rescan))
	r := scanRes{}
	for i := 0; i < 200; i++ {               // 布置了200个接受器  create 200 receiver.
		go RecvSyn(rs)
	}
	for i := 0; i < 5000; i++ {             // 布置了5000个发射器  create 5000 sender.
		go sender(jb, 5)
	}
	go sendjob(iplist, portlist, jb)
	for {
		select {
		case p := <-rs:
			if !inString(p.host, iplist) {
				continue
			}
			if !inInt(p.port, r[p.host]) {
				r[p.host] = append(r[p.host], p.port)
			}
		case <-t:
			go sendjob(iplist, portlist, jb)
		case s := <-st:
			switch s {
			case "exit":
				res <- r
				return
			case "get":
				res <- r
			default:
				continue
			}
		}
	}
}

// 以主机分组的扫描结果字符串输出
// Return a scan result string group by host.
func resString(res scanRes) string {
	var buf bytes.Buffer
	for k, v := range res {
		buf.Write([]byte(k))
		buf.Write([]byte(" :\n\t"))
		var l [][]byte
		for _, x := range v {
			l = append(l, []byte(strconv.Itoa(x)))
		}
		buf.Write(bytes.Join(l, []byte(", ")))
		buf.Write([]byte("\n"))
	}
	return buf.String()
}
// 以端口分组的扫描结果字符串输出
// Return a scan result string group by port.
func rresString(r scanResr) string {
	var buf bytes.Buffer
	for k, v := range r {
		buf.Write([]byte(strconv.Itoa(k)))
		buf.Write([]byte(" :\n\t"))
		buf.Write([]byte(strings.Join(v, ", ")))
		buf.Write([]byte("\n"))
	}
	return buf.String()
}
