<h1 align="center">cloudflare-origin-ip</h1>

<h4 align="center">Try to find the origin IP of a webapp protected by Cloudflare.</h4>

<p align="center">
    <img src="https://img.shields.io/badge/python-v3-blue" alt="python badge">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license badge">
    <a href="https://twitter.com/intent/tweet?text=https%3a%2f%2fgithub.com%2fgwen001%2fcloudflare-origin-ip%2f" target="_blank"><img src="https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Fgithub.com%2Fgwen001%2Fcloudflare-origin-ip" alt="twitter badge"></a>
</p>

<!-- <p align="center">
    <img src="https://img.shields.io/github/stars/gwen001/cloudflare-origin-ip?style=social" alt="github stars badge">
    <img src="https://img.shields.io/github/watchers/gwen001/cloudflare-origin-ip?style=social" alt="github watchers badge">
    <img src="https://img.shields.io/github/forks/gwen001/cloudflare-origin-ip?style=social" alt="github forks badge">
</p> -->

---

## Description

This Python tool compares the HTTP response of the given subdomain to HTTP responses of a list of IPs addresses. This list is based on:
- subdomains supplied by the user
- subdomains found on external sources
- IPs found external sources

Then, a score of similarity is calculated for each response using the Levenshtein algorithm.

## Install

```
git clone https://github.com/gwen001/cloudflare-origin-ip
cd cloudflare-origin-ip
pip3 install -r requirements.txt
```

Depending the sources you want to use, you'll need to create environment variables:
- Censys: `CENSYS_UID` and `CENSYS_SECRET`
- SecurityTrails: `SECURITY_TRAILS_API_KEY`

## Usage

```
$ python3 cloudflare-origin-ip.py <url>
```

```
usage: cloudflare-origin-ip.py [-h] [-u URL] [-s SOURCE]

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     url to test
  -s SOURCE, --source SOURCE
                        datas sources separated by coma, can be: censys,crtsh,securitytrails,local file

Examples:
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s censys,crtsh,securitytrails (default)
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s /home/local/ips.txt
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s censys,crtsh,/home/local/ips.txt,/home/local/subdomains.txt
```

## How it works

1/ Performs a HTTP request to the URL provided, this is the reference request.

2/ Grabs IPs using several sources:
- censys (key required)
- crtsh
- securitytrails (key required)
- local file

3/ Performs a HTTP request to all IPs grabbed with the header `Host` setted to the subdomain of the reference request.

4/ Compares the responses obtained with the response of the reference request using the `Levenshtein` algorithm.

5/ Displays a score of similarity.

---

<img src="https://raw.githubusercontent.com/gwen001/cloudflare-origin-ip/main/preview.png" />

---

Feel free to [open an issue](/../../issues/) if you have any problem with the script.  

