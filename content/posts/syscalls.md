+++
title = "Network-related Windows Syscalls"
date = "2025-07-24T14:58:49+02:00"
dateFormat = "2006-01-02" # This value can be configured for per-post date formatting
cover = ""
keywords = ["syscalls", "network", "dynamic", "analysis", "binary", "Windows"]
description = ""
showFullContent = true
readingTime = false
hideComments = false
+++

During my internship at team Carbone, we had to extract IPs and URLs from the windows system calls made by executables. (the complete report is avalaible in the [documents](/documents/) section)

This led me to establish a list of system calls from which we can find those informations in the arguments, often time as plain text or in a `sockaddr` struct (readable in memory)

As such, I decided to post this list here so that anyone can use this as a good basis for windows network syscall analysis. Here is a python dict with the list, from which you can easily deduce a json format.

```python
# contains ip-related (or host/url related) syscalls with the position of interesting arguments
ip_syscalls = {
    # icmpapi.h
    "icmpsendecho": {
        "argpos": [1],
        "argdesc": ["DestinationAdress"],
        "type": "icmp",
    },
    "icmpsendecho2": {
        "argpos": [4],
        "argdesc": ["DestinationAdress"],
        "type": "icmp",
    },
    "icmpsendecho2ex": {
        "argpos": [4, 5],
        "argdesc": ["SourceAdress", "DestinationAdress"],
        "type": "icmp",
    },
    # winhttp.h
    "winhttpconnect": {
        "argpos": [1, 2],
        "argdesc": ["pswzServerName", "nServerPort"],
        "type": "http",
    },
    "winhttpgetproxyforurl": {
        "argpos": [1],
        "argdesc": ["lpcwszUrl"],
        "type": "http",
    },
    "winhttpgetproxyforurlex": {
        "argpos": [1],
        "argdesc": ["pcwszUrl"],
        "type": "http",
    },
    # wininet.h
    "internetconnectw": {
        "argpos": [1, 2],
        "argdesc": ["lpszServerName", "nServerPort"],
        "type": "http",
    },
    "internetconnecta": {
        "argpos": [1, 2],
        "argdesc": ["lpszServerName", "nServerPort"],
        "type": "http",
    },
    "internetopenrequestw": {
        "argpos": [2],
        "argdesc": ["lpszObjectName"],
        "type": "http",
    },
    "internetopenrequesta": {
        "argpos": [2],
        "argdesc": ["lpszObjectName"],
        "type": "http",
    },
    "internetopenurla": {
        "argpos": [1],
        "argdesc": ["lpszUrl"],
        "type": "http",
    },
    "internetopenurlw": {
        "argpos": [1],
        "argdesc": ["lpszUrl"],
        "type": "http",
    },
    "internetcrackurla": {
        "argpos": [0],
        "argdesc": ["lpszUrl"],
        "type": "http",
    },
    # winsock2.h
    "inet_addr": {
        "argpos": [0],
        "argdesc": ["cp"],
        "type": "ip",
    },
    "connect": {
        "argpos": [1],
        "argdesc": ["sockaddr* name"],
        "type": "tcp/udp",
    },
    "bind": {
        "argpos": [1],
        "argdesc": ["sockaddr* name"],
        "type": "tcp/udp",
    },
    "sendto": {
        "argpos": [4],
        "argdesc": ["sockaddr* to"],
        "type": "tcp/udp",
    },
    "recvfrom": {
        "argpos": [4],
        "argdesc": ["sockaddr* from"],
        "type": "tcp/udp",
    },
    "ioctlsocket": {
        "argpos": [1,2],
        "argdesc": ["cmd","argp"],
        "type": "tcp/udp",
    },
    "wsaaccept": {
        "argpos": [1, 2],
        "argdesc": ["sockaddr* addr", "addrlen"],
        "type": "tcp/udp",
    },
    "wsaconnect": {
        "argpos": [1, 2],
        "argdesc": ["sockaddr* name", "namelen"],
        "type": "tcp/udp",
    },
    "wsaconnectbynamea": {
        "argpos": [1, 2],
        "argdesc": ["nodename", "servicename"],
        "type": "tcp/udp",
    },
    "wsaconnectbynamew": {
        "argpos": [1, 2],
        "argdesc": ["nodename", "servicename"],
        "type": "tcp/udp",
    },
    "wsaconnectbyname" : { #former alias name for wsaconnectbynamea
        "argpos": [1, 2],
        "argdesc": ["nodename", "servicename"],
        "type": "tcp/udp",
    },
    "wsaconnectbylist": {
        "argpos": [1],
        "argdesc": ["SocketAddress"],
        "type": "tcp/udp",
    },
    "wsastringtoadressa": {
        "argpos": [0],
        "argdesc": ["AddressString"],
        "type": "tcp/udp",
    },
    "wsastringtoaddressw": {
        "argpos": [0],
        "argdesc": ["AddressString"],
        "type": "tcp/udp",
    },
    # winsock.h
    "gethostbyname": {
        "argpos": [0],
        "argdesc": ["name"],
        "type": "ip",
    },
    # ws2tcpip.h
    "getaddrinfo": {
        "argpos": [0, 1],
        "argdesc": ["pNodeName", "pServiceName"],
        "type": "ip",
    },
    "getaddrinfow": {
        "argpos": [0, 1],
        "argdesc": ["pNodeName", "pServiceName"],
        "type": "ip",
    },
    "getaddrinfoexw": {
        "argpos": [0, 1],
        "argdesc": ["pName", "pServiceName"],
        "type": "ip",
    },
    "getaddrinfoexa": {
        "argpos": [0, 1],
        "argdesc": ["pName", "pServiceName"],
        "type": "ip",
    },
    "inet_ntop": {
        "argpos": [2],
        "argdesc": ["pStringBuf"],
        "type": "ip",
    },
    "inet_pton": {
        "argpos": [1],
        "argdesc": ["pszAddrString"],
        "type": "ip",
    },
    "inetptonw": {
        "argpos": [1],
        "argdesc": ["pStringBuf"],
        "type": "ip",
    },
    "inetntopw": {
        "argpos": [2],
        "argdesc": ["pszAddrString"],
        "type": "ip",
    },
    # windns.h
    "dnsquery_a": {
        "argpos": [0],
        "argdesc": ["pszName"],
        "type": "dns",
    },
    "dnsquery_w": {
        "argpos": [0],
        "argdesc": ["pszName"],
        "type": "dns",
    },
    "dnsquery_utf8": {
        "argpos": [0],
        "argdesc": ["pszName"],
        "type": "dns",
    },
    "dnssetapplicationsettings": {
        "argpos": [1],
        "argdesc": ["DNS_CUSTOM_SERVER* pServers"],
        "type": "dns",
    },
    # wtsapi32.h
    "wtsopenserverw": {
        "argpos": [0],
        "argdesc": ["pServerName"],
        "type": "rdp",
    },
    "wtsopenservera": {
        "argpos": [0],
        "argdesc": ["pServerName"],
        "type": "rdp",
    },
    "wtsopenserverexw": {
        "argpos": [0],
        "argdesc": ["pServerName"],
        "type": "rdp",
    },
    "wtsopenserverexa": {
        "argpos": [0],
        "argdesc": ["pServerName"],
        "type": "rdp",
    },
    "wtssetuserconfigw": {
        "argpos": [0],
        "argdesc": ["pServerName"],
        "type": "rdp",
    },
    "wtssetuserconfiga": {
        "argpos": [0],
        "argdesc": ["pServerName"],
        "type": "rdp",
    },
    # urlmon.h
    "urldownloadtofilew": {
        "argpos": [1],
        "argdesc": ["szURL"],
        "type": "url download",
    },
    "urldownloadtocachefilew": {
        "argpos": [1],
        "argdesc": ["szURL"],
        "type": "url download",
    },
    # lmaccess.h
    "netusergetinfo": {
        "argpos": [0],
        "argdesc": ["servername"],
        "type": "network management",
    },
    "netusergetlocalgroups": {
        "argpos": [0],
        "argdesc": ["servername"],
        "type": "network management",
    },
    "netusergetgroups": {
        "argpos": [0],
        "argdesc": ["servername"],
        "type": "network management",
    },
    # winnetwk.h
    "wnetuseconnectionw": {
        "argpos": [1],
        "argdesc": ["lpNetResource"],
        "type": "wnet",
    },
    # wincrypt.h
    "cryptreceiveobjectbyurla": {
        "argpos": [0],
        "argdesc": ["pszUrl"],
        "type": "url download",
    }
}
```

