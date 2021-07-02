package main
// http服务器文件，主要是作为接口用来返回 json 字符串的扫描结果，服务器有ACL，仅允许的IP地址能够访问并活得扫描结果
// HTTP server file, to send a JSON result string, server has an ACL to limit access to.
// Copy right wudifengz@2021
import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func StartServer(acl []string, r <-chan scanRes, rr <-chan scanResr, port int) {
	var js []byte
	var jsr []byte
	ser := &http.Server{Addr: ":" + strconv.Itoa(port), ReadTimeout: time.Second * 5, WriteTimeout: time.Second * 5}
	ser.SetKeepAlivesEnabled(false)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var m string
		rip := strings.Split(r.RemoteAddr, ":")[0]
		if r.Method == "POST" {
			if r.PostFormValue("sort") == "host" {
				m = string(js)
			} else {
				m = string(jsr)
			}
		}
		if len(acl) != 0 && !inString(rip, acl) {
			_, _ = fmt.Fprintf(w, "Welcome")
		} else {
			_, _ = fmt.Fprintf(w, m)
		}
	})
	go func() {
		for {
			select {
			case rs := <-r:
				js, _ = json.Marshal(rs)
			case p := <-rr:
				jsr, _ = json.Marshal(p)
			}
		}
	}()
	ser.ListenAndServe()
}
