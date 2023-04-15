## Aries 

<p align="center">
    <img width="120" src="image/aries.png"/>
<p>

Aries  is a free and open-source network scanner. Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the responses.

## Features
- Get ports from **FOFA** 
- **SYN/CONNECT** Scanning Mode
- **Nmap Service Probes** (**experimental**)
- Output format support `txt` `json` `csv`
- API (ToDo)

## Prerequisite
If the error is as follows:
> **Error** ./aries: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./aries)

> **Error** ./aries: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./aries)

The solution is as follows:

To install libcap on Linux: `sudo apt install -y libpcap-dev`, on Mac: `sudo brew install libpcap`

## Example

```
aries -t 192.168.88.1/24
aries -t 192.168.88.1/24,192.168.66.1/24
aries -t example.com,scanme.nmap.org
```
Skip Host Discovery
```
aries -t 192.168.88.168 -Pn
```

Hosts File
```
aries -T file.txt

cat ./file.txt
example.com
scanme.nmap.org
```

Ports File
```
aries -t 192.168.88.168

cat ./ports.txt
80,443,1433,8000-8100
```

Port Range
```
aries -t 192.168.88.168 -p 80,443,8000-8100
aries -t 192.168.88.168 -p - # 1-65535
aries -t 192.168.88.168 -tp 1000 # top 1000 ports
aries -t 192.168.88.168 -tp full # 1-65535
aries -t 192.168.88.168 -tp hotel
aries -t 192.168.88.168 -tp database
aries -t 192.168.88.168 -tp ics
aries -t 192.168.88.168 -tp iot
aries -t 192.168.88.168 -tp mini
```

Output File
```
aries -t 192.168.88.168 -o r.txt
aries -t 192.168.88.168 -o r.json
aries -t 192.168.88.168 -o r.csv
```

Exclude Hosts
```
aries -t 192.168.88.168/24 -eh 192.168.88.254,192.168.88.1
aries -t 192.168.88.168/24 -ef filter.txt
cat ./filter.txt
192.168.88.254
192.168.88.1
```

Exclude Ports
```
aries -t 192.168.88.168/24 -ep 110,25,53
aries -t 192.168.88.168/24 -pf filter.txt
cat ./filter.txt
110
25
53
```

Rate Limit
```
aries -t 192.168.88.168/24 -rate 2000
```


## Reference
- [naabu](https://github.com/projectdiscovery/naabu)
- [vscan-go](https://github.com/RickGray/vscan-go)