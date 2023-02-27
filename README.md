## Aries 

<p align="center">
    <img width="120" src="image/aries2.png"/>
<p>

Aries  is a free and open-source network scanner. Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the responses.

## Features
- SYN (Silent) Scanning Mode

## Prerequisite
If the error is as follows:
> **Error** ./aries: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./aries)

> **Error** ./aries: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./aries)

The solution is as follows:

To install libcap on Linux: `sudo apt install -y libpcap-dev`, on Mac: `sudo brew install libpcap`

## Reference
- [naabu](https://github.com/projectdiscovery/naabu)