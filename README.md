# synscanner
A SYN scanner to scan the net, find target and find which port target open.

like : nmap -Ss -Pn .......  

MeanWhile start a HTTP Server to get the result by JSON string. There are 2 type of JSON string format, host ->[]ports and port -> []hosts. The posted "sort" value control the type, "host" for first, nothing for secentd.

*** YES !!! there is a http-server to get the result by json string. ***

一个半开连接扫描器，我不知道它又多快（毕竟没测过），能够扫描网络上的IP地址和端口。
同时这里还启动了一个 HTTP 服务器，可以返回 2 种格式的 JSON 格式的数据，host ->[]ports and port -> []hosts,由 POST 到服务器的 “sort” 参数值控制，如果值是 "host" 则返回第一种，空值返回第二种。
HTTP 服务器支持 ACL 可以限定访问 IP 地址段。
