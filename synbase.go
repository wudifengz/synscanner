package main
// 基础SYN扫描文件，包含 SYN 包构造函数、SYN数据包发送函数，接收SYN-ACK数据包函数.
// 这里主要借鉴了 GOMAP 项目的SYN发送接受函数。
// Base SYN scanner file, include SYN package create function, SYN package send function, SYN-ACK package receive function.
// Some modified function reference from GOMAP project on Github, do some change for this project.
// Copy right wudifengz@2021
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type tcpOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}
type tcppack struct {
	sport uint16
	dport uint16
	seqnu uint32
	aseqn uint32
	flag  uint16
	wsize uint16
	sumnu uint16
	ugpoi uint16
}

//获取当前设备可用网络端口并返回
func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), err
			}
		}
	}
	return "", fmt.Errorf("No IP Found")
}

//针对TCP头的校验。TCP校验位包含伪头部（pseudoHeader）
func checkSum(data []byte, src, dst [4]byte) uint16 {
	pseudoHeader := []byte{
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3],
		0,
		6,
		0,
		byte(len(data)),
	}

	totalLength := len(pseudoHeader) + len(data)
	if totalLength%2 != 0 {
		totalLength++
	}

	d := make([]byte, 0, totalLength)
	d = append(d, pseudoHeader...)
	d = append(d, data...)

	var sum uint32
	for i := 0; i < len(d)-1; i += 2 {
		sum += uint32(uint16(d[i])<<8 | uint16(d[i+1]))
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}

//把IP地址字符串变成4个字节的数值
func ipstr2Bytes(addr string) [4]byte {
	ip := net.ParseIP(addr)
	return [4]byte{ip[12], ip[13], ip[14], ip[15]}
}

//发送函数，用来发送SYN包
//ips参数为目标IP地址，ports参数为目标端口
func SendSyn(ips string, ports int) error {
	laddr, err := getLocalIP()
	if err != nil {
		return err
	}
	conn, err := net.Dial("ip4:tcp", ips)
	if err != nil {
		return err
	}
	defer conn.Close()
	t := tcppack{sport: 34567, dport: uint16(ports), seqnu: 0, aseqn: 0, flag: 0x8002, wsize: 65535, sumnu: 0, ugpoi: 0}
	op := []tcpOption{
		{
			Kind:   2,
			Length: 4,
			Data:   []byte{0x05, 0xb4},
		},
		{
			Kind: 0,
		},
	}
	var buffer bytes.Buffer
	_ = binary.Write(&buffer, binary.BigEndian, t)
	for i := range op {
		binary.Write(&buffer, binary.BigEndian, op[i].Kind)
		binary.Write(&buffer, binary.BigEndian, op[i].Length)
		binary.Write(&buffer, binary.BigEndian, op[i].Data)
	}
	binary.Write(&buffer, binary.BigEndian, [6]byte{})
	t.sumnu = checkSum(buffer.Bytes(), ipstr2Bytes(laddr), ipstr2Bytes(ips))
	var buff bytes.Buffer
	binary.Write(&buff, binary.BigEndian, t)

	for i := range op {
		binary.Write(&buff, binary.BigEndian, op[i].Kind)
		binary.Write(&buff, binary.BigEndian, op[i].Length)
		binary.Write(&buff, binary.BigEndian, op[i].Data)
	}
	binary.Write(&buff, binary.BigEndian, [6]byte{})

	if _, err = conn.Write(buff.Bytes()); err != nil {
		return err
	}
	return nil
}

//接收函数，用来接受端口的SYN-ACK信息。
//ips 为目标IP地址，ports为目标端口，res为用来多线程传递参数的通道
func RecvSyn(res chan<- popen) {
	laddr, _ := getLocalIP()
	listenAddr, _ := net.ResolveIPAddr("ip4", laddr)
	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer conn.Close()
	var po popen
	for {
		buff := make([]byte, 1024)
		_, addr, err := conn.ReadFrom(buff)
		if err != nil {
			continue
		}
		if buff[13] != 0x12 {
			continue
		}
		var p uint16
		binary.Read(bytes.NewReader(buff), binary.BigEndian, &p)
		po.host = addr.String()
		po.port = int(p)
		po.status = true
		res <- po
	}
}
