<h1 align="center">FinalRecon</h1>

<h4 align="center">
OSINT Tool for All-In-One Web Reconnaissance
</h4>

<p align="center">
<img src="https://img.shields.io/badge/Python-3-brightgreen.svg?style=plastic">
<img src="https://img.shields.io/badge/OSINT-red.svg?style=plastic">
<img src="https://img.shields.io/badge/Web-red.svg?style=plastic">
</p>

FinalRecon is a fast and simple python script for web reconnaissance. It follows a modular structure so in future new modules can be added with ease.

## Features

FinalRecon provides detailed information such as :

### Header Information
<p align="center"><img src="https://i.imgur.com/B7sblDP.png"></p>

### WHOIS
<p align="center"><img src="https://i.imgur.com/cDEJ79H.png"></p>

### SSL Certificate Details
<p align="center"><img src="https://i.imgur.com/PFZm0qx.png"></p>
<p align="center">Found Flag in SSL Certificate - Securinets CTF 2019</p>

### Crawler
<p align="center"><img src="https://i.imgur.com/C8eQ8z3.png">

#### More modules will be added in future

## Tested on

* Kali Linux 2019.1

## Installation

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
```
## Usage

```bash
python3 finalrecon.py -h
usage: finalrecon.py [-h] [--headers] [--sslinfo] [--whois] [--crawl] [--full]
                     url

FinalRecon - OSINT Tool for All-In-One Web Recon | v1.0.0

positional arguments:
  url         Target URL

optional arguments:
  -h, --help  show this help message and exit
  --headers   Get Header Information
  --sslinfo   Get SSL Certificate Information
  --whois     Get Whois Lookup
  --crawl     Crawl Target Website
  --full      Get Full Analysis, Test All Available Options
```

## Demo
