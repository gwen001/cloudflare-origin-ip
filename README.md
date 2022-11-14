# cloudflare-origin-ip

Try to find the origin IP of a website protected by Cloudflare.

## Install

```bash
git clone https://github.com/gwen001/cloudflare-origin-ip
cd cloudflare-origin-ip
pip3 install -r requirements.txt
```

## Usage

```bash
$ python3 cloudflare-origin-ip.py <url>
```

```
usage: cloudflare-origin-ip.py [-h] [-u URL] [-s SOURCE]

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     url to test
  -s SOURCE, --source SOURCE
                        datas sources separated by coma, can be: censys,crtsh,local file

Examples:
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s censys,crtsh (default)
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s /home/local/ips.txt
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s censys,crtsh,/home/local/ips.txt,/home/local/subdomains.txt
```

<img src="https://raw.githubusercontent.com/gwen001/cloudflare-origin-ip/main/preview.png" />
