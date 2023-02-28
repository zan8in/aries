## Aries 

<p align="center">
    <img width="120" src="image/aries2.png"/>
<p>

Aries  is a free and open-source network scanner. Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the responses.

## Features
- SYN (Silent) Scanning Mode
- Output format support `txt` `json` `csv`
- API (ToDo)

## Prerequisite
If the error is as follows:
> **Error** ./aries: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./aries)

> **Error** ./aries: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./aries)

The solution is as follows:

To install libcap on Linux: `sudo apt install -y libpcap-dev`, on Mac: `sudo brew install libpcap`

## Example
Basic usage
```
aries -t 192.168.88.1/24 # default top 100 ports
aries -t example.com,hackerone.com -p - # scan all ports (1-65535)
aries -T file.txt -tp 1000 # scan top 1000 ports
```

Advanced usage
```
# send 5000 packets to send per second (default 1000)
aries -t 192.168.88.1/24 -rate 5000 
```


## Reference
- [naabu](https://github.com/projectdiscovery/naabu)