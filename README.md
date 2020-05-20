<p align="center"><img src="https://i.imgur.com/rLENhCp.jpg"></p>

<p align="center">
<img src="https://img.shields.io/badge/Python-3-brightgreen.svg?style=plastic">
<img src="https://img.shields.io/badge/OSINT-red.svg?style=plastic">
<img src="https://img.shields.io/badge/Web-red.svg?style=plastic">
</p>

<p align="center">
  <a href="https://twitter.com/thewhiteh4t"><b>Twitter</b></a>
  <span> - </span>
  <a href="https://t.me/thewhiteh4t"><b>Telegram</b></a>
  <span> - </span>
  <a href="https://thewhiteh4t.github.io"><b>thewhiteh4t's Blog</b></a>
</p>

| Available | in | |
|-|-|-|
| [BlackArch Linux](https://blackarch.org/) | [SecBSD](https://secbsd.org/) | [Tsurugi Linux](https://tsurugi-linux.org/) |
| ![BlackArch Linux](https://i.imgur.com/1wJVDV5.png) | ![SecBSD](https://i.imgur.com/z36xL8c.png) | ![Tsurugi Linux](https://i.imgur.com/S1ylcp7.jpg) |
| [Ninjutsu OS](https://ninjutsu-os.github.io/) | | |
| ![Ninjutsu OS](https://i.imgur.com/Xg54FDS.png) | | |

FinalRecon is a fast and simple python script for web reconnaissance. It follows a modular structure so in future new modules can be added with ease.

## Featured

### Python For OSINT
* Hakin9 April 2020
* https://hakin9.org/product/python-for-osint-tooling/

### NullByte
* https://null-byte.wonderhowto.com/how-to/conduct-recon-web-target-with-python-tools-0198114/
* https://www.youtube.com/watch?v=F9lwzMPGIgo

### Hakin9
* https://hakin9.org/final-recon-osint-tool-for-all-in-one-web-reconnaissance/

## Features

FinalRecon provides detailed information such as :

* Header Information

* Whois

* SSL Certificate Information

* Crawler
  * html
    * CSS
    * Javascripts
    * Internal Links
    * External Links
    * Images
  * robots
  * sitemaps
  * Links inside Javascripts
  * Links from Wayback Machine from Last 1 Year

* DNS Enumeration
  * A, AAAA, ANY, CNAME, MX, NS, SOA, TXT Records
  * DMARC Records

* Subdomain Enumeration
  * Data Sources
    * BuffOver
    * crt.sh
    * ThreatCrowd
    * AnubisDB
    * ThreatMiner
    * Facebook Certificate Transparency API
      * Auth Token is Required for this source, read Configuration below

* Traceroute
  * Protocols
    * UDP
    * TCP
    * ICMP

* Directory Searching
  * Support for File Extensions
  * Directories from Wayback Machine from Last 1 Year

* Port Scan
  * Fast
  * Top 1000 Ports
  * Open Ports with Standard Services

* Export
  * Formats
    * txt
    * xml
    * csv

## Configuration

### API Keys

Some Modules Use API Keys to fetch data from different resources, these are optional, if you are not using an API key, they will be simply skipped.
If you are interested in using these resources you can store your API key in **keys.json** file.

`Path --> finalrecon/conf/keys.json`

If you dont want to use a key for a certain data source just set its value to `null`, by default values of all available data sources are null.

#### Facebook Developers API

This data source is used to fetch **Certificate Transparency** data which is used in **Subdomain Enumeration**

Key Format : `APP-ID|APP-SECRET`

Read More : https://developers.facebook.com/docs/facebook-login/access-tokens

## Tested on

* Kali Linux
* BlackArch Linux

> FinalRecon is a tool for **Pentesters** and it's designed for **Linux** based Operating Systems, other platforms like **Windows** and **Termux** are **NOT** supported.

## Installation

### BlackArch Linux

```
pacman -S finalrecon
```

### SecBSD

```bash
doas pkg_add finalrecon
```

### Kali Linux

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
```

### Docker

```
docker pull thewhiteh4t/finalrecon
docker run -it --entrypoint /bin/sh thewhiteh4t/finalrecon
```

## Usage

```bash
python3 finalrecon.py -h

usage: finalrecon.py [-h] [--headers] [--sslinfo] [--whois] [--crawl] [--dns] [--sub] [--trace] [--dir] [--ps]
                     [--full] [-t T] [-T T] [-w W] [-r] [-s] [-d D] [-e E] [-m M] [-p P] [-tt TT] [-o O]
                     url

FinalRecon - The Last Recon Tool You Will Need | v1.0.7

positional arguments:
  url         Target URL

optional arguments:
  -h, --help  show this help message and exit
  --headers   Header Information
  --sslinfo   SSL Certificate Information
  --whois     Whois Lookup
  --crawl     Crawl Target
  --dns       DNS Enumeration
  --sub       Sub-Domain Enumeration
  --trace     Traceroute
  --dir       Directory Search
  --ps        Fast Port Scan
  --full      Full Recon

Extra Options:
  -t T        Number of Threads [ Default : 30 ]
  -T T        Request Timeout [ Default : 30.0 ]
  -w W        Path to Wordlist [ Default : wordlists/dirb_common.txt ]
  -r          Allow Redirect [ Default : False ]
  -s          Toggle SSL Verification [ Default : True ]
  -d D        Custom DNS Servers [ Default : 1.1.1.1 ]
  -e E        File Extensions [ Example : txt, xml, php ]
  -m M        Traceroute Mode [ Default : UDP ] [ Available : TCP, ICMP ]
  -p P        Port for Traceroute [ Default : 80 / 33434 ]
  -tt TT      Traceroute Timeout [ Default : 1.0 ]
  -o O        Export Output [ Default : txt ] [ Available : xml, csv ]
```

```bash
# Check headers

python3 finalrecon.py --headers <url>

# Check ssl Certificate

python3 finalrecon.py --sslinfo <url>

# Check whois Information

python3 finalrecon.py --whois <url>

# Crawl Target

python3 finalrecon.py --crawl <url>

# Directory Searching

python3 finalrecon.py --dir <url> -e txt,php -w /path/to/wordlist

# full scan

python3 finalrecon.py --full <url>
```

## Demo
[![Youtube](https://i.imgur.com/IQpZ67e.png)](https://www.youtube.com/watch?v=10q_CKnM3x4)
