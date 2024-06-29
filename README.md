<p align="center"><img src="https://i.imgur.com/rLENhCp.jpg"></p>

<p align="center">
<img src="https://img.shields.io/badge/Python-3-brightgreen.svg?style=plastic">
<img src="https://img.shields.io/badge/All In One-red.svg?style=plastic">
<img src="https://img.shields.io/badge/Web Recon-red.svg?style=plastic">
</p>

<p align="center">
  <a href="https://twitter.com/thewhiteh4t"><b>Twitter</b></a>
  <span> - </span>
  <a href="https://t.me/thewhiteh4t"><b>Telegram</b></a>
  <span> - </span>
  <a href="https://thewhiteh4t.github.io"><b>thewhiteh4t's Blog</b></a>
</p>

FinalRecon is an all in one **automatic web reconnaissance** tool written in python. Goal of FinalRecon is to provide an **overview** of the target in a **short** amount of time while maintaining the **accuracy** of results. Instead of executing **several tools** one after another it can provide similar results keeping dependencies **small and simple**.

## Available In

<p align="center">
  <a href="https://www.kali.org/news/kali-linux-2020-4-release/">
    <img width="150px" hspace="10px" src="https://i.imgur.com/teSiL4p.png" alt="kali linux finalrecon">
  </a>
  <a href="https://blackarch.org/">
    <img width="150px" hspace="10px" src="https://i.imgur.com/YZ5KDL1.png" alt="blackarch finalrecon">
  </a>
  <a href="https://secbsd.org/">
    <img width="150px" hspace="10px" src="https://i.imgur.com/z36xL8c.png" alt="secbsd finalrecon">
  </a>
</p>

## Featured On

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
  * Over 40 types of Records are queried
  * DMARC Records

* Subdomain Enumeration
  * Over 10 reliable data sources

* Directory Enumeration
  * Support for File Extensions

* Wayback Machine
    * URLs from Last 5 Years

* Port Scan
  * Fast
  * Top 1000 Ports

* Export
  * Formats
    * txt
    * json [Coming Soon]

## Configuration

### API Keys

Some Modules Use API Keys to fetch data from different resources, these are optional, if you are not using an API key, they will be simply skipped.

#### Environment Variables

Keys are read from environment variables if they are set otherwise they are loaded from the config directory

```bash
FR_BEVIGIL_KEY, FR_BINEDGE_KEY, FR_FB_KEY, FR_HUNTER_KEY,
FR_NETLAS_KEY, FR_SHODAN_KEY, FR_VT_KEY, FR_ZOOMEYE_KEY

# Example :

export FR_SHODAN_KEY="kl32lcdqwcdfv"
```

#### Saved Keys

You can use **`-k`** to add the keys which will be saved in config directory automatically

```bash
# Usage
python3 finalrecon.py -k '<API NAME>@<API KEY>'

Valid Keys : 'bevigil', 'binedge', 'facebook', 'hunter', 'netlas','shodan', 'virustotal', 'zoomeye'

# Example :
python3 finalrecon.py -k 'shodan@kl32lcdqwcdfv'
```

`Path = $HOME/.config/finalrecon/keys.json`

| Source | Module | Link |
|--------|--------|------|
| Facebook | Sub Domain Enum | https://developers.facebook.com/docs/facebook-login/access-tokens |
| VirusTotal | Sub Domain Enum | https://www.virustotal.com/gui/my-apikey |
| Shodan | Sub Domain Enum | https://developer.shodan.io/api/requirements |
| BeVigil | Sub Domain Enum | https://bevigil.com/osint-api |
| BinaryEdge | Sub Domain Enum | https://app.binaryedge.io/ |
| Netlas | Sub Domain Enum | https://docs.netlas.io/getting_started/ |
| ZoomEye | Sub Domain Enum | https://www.zoomeye.hk/ |
| Hunter | Sub Domain Enum | https://hunter.how/search-api |

### JSON Config File

Default config file is available at `~/.config/finalrecon/config.json`

```json
{
    "common": {
        "timeout": 30,
        "dns_servers": "8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1"
    },
    "ssl_cert": {
        "ssl_port": 443
    },
    "port_scan": {
        "threads": 50
    },
    "dir_enum": {
        "threads": 50,
        "redirect": false,
        "verify_ssl": false,
        "extension": ""
    },
    "export": {
        "format": "txt"
    }
}
```

## Tested on

* Kali Linux
* BlackArch Linux

> FinalRecon is a tool for **Pentesters** and it's designed for **Linux** based Operating Systems, other platforms like **Windows** and **Termux** are **NOT** supported.

## Installation

### Kali Linux

```
sudo apt install finalrecon
```

### BlackArch Linux

```
sudo pacman -S finalrecon
```

### SecBSD

```bash
doas pkg_add finalrecon
```

### Other Linux

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
```

### Docker

``` bash
docker pull thewhiteh4t/finalrecon
docker run -it --entrypoint /bin/sh thewhiteh4t/finalrecon
```

Also docker user can use this alias to run the finalrecon as the normal CLI user.

``` bash
alias finalrecon="docker run -it --rm --name finalrecon  --entrypoint 'python3' thewhiteh4t/finalrecon finalrecon.py"
```

And then use `finalrecon` to start your scan.

> remark
>
> If you have any api keys you can easily commit that image in your local machine.
>
> This docker usage needs root to run docker command.

## Usage

```bash
FinalRecon - All in One Web Recon | v1.1.6

options:
  -h, --help  show this help message and exit
  --url URL   Target URL
  --headers   Header Information
  --sslinfo   SSL Certificate Information
  --whois     Whois Lookup
  --crawl     Crawl Target
  --dns       DNS Enumeration
  --sub       Sub-Domain Enumeration
  --dir       Directory Search
  --wayback   Wayback URLs
  --ps        Fast Port Scan
  --full      Full Recon

Extra Options:
  -nb         Hide Banner
  -dt DT      Number of threads for directory enum [ Default : 30 ]
  -pt PT      Number of threads for port scan [ Default : 50 ]
  -T T        Request Timeout [ Default : 30.0 ]
  -w W        Path to Wordlist [ Default : wordlists/dirb_common.txt
              ]
  -r          Allow Redirect [ Default : False ]
  -s          Toggle SSL Verification [ Default : True ]
  -sp SP      Specify SSL Port [ Default : 443 ]
  -d D        Custom DNS Servers [ Default : 1.1.1.1 ]
  -e E        File Extensions [ Example : txt, xml, php ]
  -o O        Export Format [ Default : txt ]
  -cd CD      Change export directory [ Default :
              ~/.local/share/finalrecon ]
  -k K        Add API key [ Example : shodan@key ]
```

```bash
# Check headers

python3 finalrecon.py --headers --url https://example.com

# Check ssl Certificate

python3 finalrecon.py --sslinfo --url https://example.com

# Check whois Information

python3 finalrecon.py --whois --url https://example.com

# Crawl Target

python3 finalrecon.py --crawl --url https://example.com

# Directory Searching

python3 finalrecon.py --dir --url https://example.com -e txt,php -w /path/to/wordlist

# full scan

python3 finalrecon.py --full --url https://example.com
```

## Demo
[![Odysee](https://i.imgur.com/IQpZ67e.png)](https://odysee.com/@thewhiteh4t:2/what%27s-new-in-finalrecon-v1.0.2-osint:c)
