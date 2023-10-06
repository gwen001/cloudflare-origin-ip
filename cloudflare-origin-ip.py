#!/usr/bin/python3

import os
import sys
import json
import requests
import tldextract
import socket
import argparse
import threading
import time
import ipaddress
import textwrap
from functools import partial
# from urlparse import urlparse
from urllib import parse
from termcolor import colored
from netaddr import *
from multiprocessing.dummy import Pool

# disable "InsecureRequestWarning: Unverified HTTPS request is being made."
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def banner():
	print("""
        _                 _  __ _                              _       _          _
    ___| | ___  _   _  __| |/ _| | __ _ _ __ ___     ___  _ __(_) __ _(_)_ __    (_)_ __        _ __  _   _
   / __| |/ _ \| | | |/ _` | |_| |/ _` | '__/ _ \   / _ \| '__| |/ _` | | '_ \   | | '_ \      | '_ \| | | |
  | (__| | (_) | |_| | (_| |  _| | (_| | | |  __/  | (_) | |  | | (_| | | | | |  | | |_) |  _  | |_) | |_| |
   \___|_|\___/ \__,_|\__,_|_| |_|\__,_|_|  \___|   \___/|_|  |_|\__, |_|_| |_|  |_| .__/  (_) | .__/ \__, |
                                                                 |___/             |_|         |_|    |___/

                                by @gwendallecoguic

""")
	pass

banner()


TEST_BYPASS = 1
GOOD_CANDIDATE_SCORE = 80
COMPARE_FIRST_CHARS = 1000
REQUEST_TIMEOUT = 3
MAX_THREADS = 10

# COEF_STATUS_CODE = 0.5
# COEF_CONTENT = 1
# COEF_HEADERS = 0.8
# COEF_CONTENT_TYPE = 0.6

# COEF_STATUS_CODE = 1
# COEF_CONTENT = 2
# COEF_HEADERS = 1.5
# COEF_CONTENT_TYPE = 1.3

r_cloudflare = [
    # ipv4
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '108.162.192.0/18',
    '131.0.72.0/22',
    '141.101.64.0/18',
    '162.158.0.0/15',
    '172.64.0.0/13',
    '173.245.48.0/20',
    '188.114.96.0/20',
    '190.93.240.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    # ipv6
    '2400:cb00::/32',
    '2606:4700::/32',
    '2803:f800::/32',
    '2405:b500::/32',
    '2405:8100::/32',
    '2a06:98c0::/29',
    '2c0f:f248::/32',
]
r_cloudflare_i = [
    # ipv4
    [1729491968,1729492991],
    [1729546240,1729547263],
    [1730085888,1730086911],
    [1745879040,1746403327],
    [1746403328,1746665471],
    [1822605312,1822621695],
    [2197833728,2197834751],
    [2372222976,2372239359],
    [2728263680,2728394751],
    [2889875456,2890399743],
    [2918526976,2918531071],
    [3161612288,3161616383],
    [3193827328,3193831423],
    [3320508416,3320509439],
    [3324608512,3324641279],
    # ipv6 ?
]

r_cloudflare6 = [
]

t_exclude_headers = [
    'Set-Cookie', 'Date', 'Last-Modified', 'Expires', 'Age', 'CF-RAY'
]

parser = argparse.ArgumentParser( formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent('''Examples:
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s censys,crtsh,securitytrails (default)
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s /home/local/ips.txt
cloudflare-origin-ip.py -u https://xxx.xxxxxxxxxxxx.xxx -s censys,crtsh,/home/local/ips.txt,/home/local/subdomains.txt

Note that this is an automated tool, manual check is still required.
''') )
parser.add_argument( "-u","--url",help="url to test" )
parser.add_argument( "-s","--source",help="datas sources separated by coma, can be: censys,crtsh,local file" )
parser.parse_args()
args = parser.parse_args()

if args.url:
    url = args.url
else:
    parser.error( 'host is missing <www.example.com>' )

if args.source:
    t_sources = args.source.split( ',' )
else:
    t_sources = [ 'censys', 'crtsh', 'securitytrails' ]

if 'censys' in t_sources:
    try:
        CENSYS_UID = os.environ['CENSYS_UID']
        CENSYS_SECRET = os.environ['CENSYS_SECRET']
    except Exception as e:
        t_sources.remove('censys')
        print( colored("[-] error occured: CENSYS_UID or CENSYS_SECRET not found, Censys removed from sources", 'red') )
        # print( "Error: %s not defined" % e )
        # print( "To fix this:" )
        # print( "export CENSYS_UID=xxxxxxxxxxxxxxxxxxxxxxxxxx" )
        # print( "export CENSYS_SECRET=xxxxxxxxxxxxxxxxxxxxxxx" )
        # exit()

if 'securitytrails' in t_sources:
    try:
        SECURITY_TRAILS_API_KEY = os.environ['SECURITY_TRAILS_API_KEY']
    except Exception as e:
        t_sources.remove('securitytrails')
        print( colored("[-] error occured: SECURITY_TRAILS_API_KEY not found, SecurityTrails removed from sources", 'red') )
        # print( "Error: %s not defined" % e )
        # print( "To fix this:" )
        # print( "export SECURITY_TRAILS_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxx" )
        # exit()

# https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
def IP2Int(ip):
    o = list( map(int, ip.split('.')) )
    res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
    return res

def Int2IP(ipnum):
    o1 = int(ipnum / 16777216) % 256
    o2 = int(ipnum / 65536) % 256
    o3 = int(ipnum / 256) % 256
    o4 = int(ipnum) % 256
    return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()


# https://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Levenshtein_distance#Python
def levenshtein(s, t):
        ''' From Wikipedia article; Iterative with two matrix rows. '''
        if s == t: return 0
        elif len(s) == 0: return len(t)
        elif len(t) == 0: return len(s)
        v0 = [None] * (len(t) + 1)
        v1 = [None] * (len(t) + 1)
        for i in range(len(v0)):
            v0[i] = i
        for i in range(len(s)):
            v1[0] = i + 1
            for j in range(len(t)):
                cost = 0 if s[i] == t[j] else 1
                v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
            for j in range(len(v0)):
                v0[j] = v1[j]

        return v1[len(t)]


def grabber_crtsh( domain ):
    global t_subs, t_ips
    print( "[+] Grab data from crt.sh" )

    n_subs = 0
    n_ips = 0
    url = 'https://crt.sh/?q=%25.' + domain + '&output=json'

    try:
        ex = 0
        r = requests.get( url )
    except Exception as e:
        ex = 1
        print( colored("[-] error occured: %s" % e, 'red') )

    if ex == 0 and r.status_code == 200:
        j = r.json()
        for item in j:
            parse = tldextract.extract( item['name_value'] )
            sub = item['name_value'].replace( '*.', '' )
            if sub != domain and not sub in t_subs:
                n_subs = n_subs + 1
                t_subs.append( sub )
                try:
                    ex = 0
                    data = socket.gethostbyname( sub )
                    if not data in t_ips:
                        n_ips = n_ips + 1
                        t_ips.append( data )
                except Exception as e:
                    ex = 1

    print( colored("[+] %d subdomains found, %d ips added" % (n_subs,n_ips), 'green') )


def grabber_censys( domain ):
    global t_subs, t_ips
    print( "[+] Grab data from Censys" )

    n_ips = 0
    query = {"query":domain}
    headers = {"Content-Type":"application/json"}

    try:
        ex = 0
        r = requests.get( 'https://search.censys.io/api/v2/hosts/search?q='+domain, headers=headers, auth=(CENSYS_UID,CENSYS_SECRET) )
    except Exception as e:
        ex = 1
        print( colored("[-] error occurred: %s" % e, 'red') )

    if ex == 0 and r.status_code == 200:
        j = r.json()
        if int(j['code']) == 200 and j['status'] == 'OK' and type(j['result']) is dict and len(j['result'])>0 and type(j['result']['hits']) is list and len(j['result']['hits'])>0:
            for i in j['result']['hits']:
                n_ips = n_ips + 1
                t_ips.append( i['ip'] )

    print( colored("[+] %d ips added" % (n_ips), 'green') )


def grabber_securitytrails( domain ):
    global t_subs, t_ips
    print( "[+] Grab data from SecurityTrails" )

    n_subs = 0
    n_ips = 0
    headers = {"apikey":SECURITY_TRAILS_API_KEY}

    try:
        ex = 0
        r = requests.get( 'https://api.securitytrails.com/v1/domain/'+domain, headers=headers )
    except Exception as e:
        ex = 1
        print( colored("[-] error occurred: %s" % e, 'red') )

    if ex == 0 and r.status_code == 200:
        j = r.json()
        # print(j)
        if 'apex_domain' in j and j['apex_domain'] == domain and 'current_dns' in j:
            if 'a' in j['current_dns'] and 'values' in j['current_dns']['a']:
                for value in j['current_dns']['a']['values']:
                    if not ip in t_ips:
                        n_ips = n_ips + 1
                        t_ips.append( value['ip'] )
            if 'aaaa' in j['current_dns'] and 'values' in j['current_dns']['aaaa']:
                for value in j['current_dns']['aaaa']['values']:
                    if not ip in t_ips:
                        n_ips = n_ips + 1
                        t_ips.append( value['ipv6'] )
            if 'mx' in j['current_dns'] and 'values' in j['current_dns']['mx']:
                for value in j['current_dns']['mx']['values']:
                    try:
                        data = socket.gethostbyname( value['hostname'] )
                        if not data in t_ips:
                            n_ips = n_ips + 1
                            t_ips.append( data )
                    except Exception as e:
                        pass

    try:
        ex = 0
        r = requests.get( 'https://api.securitytrails.com/v1/domain/'+domain+'/subdomains', headers=headers )
    except Exception as e:
        ex = 1
        print( colored("[-] error occurred: %s" % e, 'red') )

    if ex == 0 and r.status_code == 200:
        j = r.json()
        # print(j)
        if 'subdomain_count' in j and j['subdomain_count'] > 0 and 'subdomains' in j:
            for prefix in j['subdomains']:
                sub = prefix + '.' + domain
                if not sub in t_subs:
                    n_subs = n_subs + 1
                    t_subs.append( sub )
                    try:
                        data = socket.gethostbyname( sub )
                        if not data in t_ips:
                            n_ips = n_ips + 1
                            t_ips.append( data )
                    except Exception as e:
                        pass

    print( colored("[+] %d subdomains found, %d ips added" % (n_subs,n_ips), 'green') )


def readIPfromFile( domain, ipsrc ):
    print( "[+] Reading datas from file: %s" % ipsrc )
    n = 0
    s = 0
    f = open( ipsrc, 'r' )
    for ip in f:
        if domain in ip:
            try:
                ex = 0
                s = s + 1
                ip = socket.gethostbyname( ip.strip() )
            except Exception as e:
                ex = 1
                ip = ''

        ip = ip.strip()
        if ip != '' and not ip in t_ips:
            n = n + 1
            t_ips.append( ip )
    print( colored("[+] %d subdomains found, %d ips added" % (s,n), 'green') )


# def is_cloudflare( ip ):
#     for r in r_cloudflare:
#         ipn = IPNetwork( r )
#         if ip in list(ipn):
#             return 1
#     return 0

# def is_cloudflare2( ip ):
#     ip = IP2Int( str(ip) )
#     for r in r_cloudflare_i:
#         if ip >= r[0] and ip <= r[1]:
#             return 1
#     return 0


# def is_cloudflare3( ip ):
#     ip = IP2Int( str(ip) )
#     for r in r_cloudflare_i:
#         if ip >= r[0] and ip <= r[1]:
#             return 1
#     return 0

# https://github.com/gwen001/cloudflare-origin-ip/pull/8
def is_cloudflare4( ip ):
    # print(ip)
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        # Handle the case when the IP address is not valid
        print( colored("[-] %s: ValueError" % (ip), 'red') )
        return False

    for r in r_cloudflare:
        if ip_obj in ipaddress.ip_network(r):
            return True

    return False


# def testBypass( r_reference, ip, host ):
#     u = 'https://' + ip
#     headers = {"Host":host}
#     try:
#         ex = 0
#         r = requests.get( u, headers=headers, timeout=REQUEST_TIMEOUT, verify=False )
#     except Exception as e:
#         ex = 1
#         print( colored("[-] %s: %s" % (ip,e), 'red') )
#     if ex == 0:
#         if not 'Content-Type' in r.headers:
#             r.headers['Content-Type'] = ''
#         score = responseCompare( r_reference, r )
#         if score['average'] > GOOD_CANDIDATE_SCORE:
#             sys.stdout.write( colored("%s" % ip, 'green') )
#             sys.stdout.write( " is a GOOD candidate with an average similarity of %d%%\n" % score['average'] )
#         else:
#             sys.stdout.write( "%s" % ip )
#             sys.stdout.write( " is not a good candidate with an average similarity of %d%%\n" % score['average'] )
#         print( colored("Status=%d (%d%%), Length=%d (%d%%), Headers=%d (%d%%), Content-Type=%s (%d%%)" % (r.status_code,score['dist_status_code'],len(r.content),score['dist_content'],len(r.headers),score['dist_headers'],r.headers['Content-Type'],score['dist_content_type']), 'white') )


# def testBypass2( t_multiproc, r_reference, host, ip ):
#     sys.stdout.write( 'progress: %d/%d\r' %  (t_multiproc['n_current'],t_multiproc['n_total']) )
#     t_multiproc['n_current'] = t_multiproc['n_current'] + 1

#     u = 'https://' + ip
#     headers = {"Host":host}
#     headers.update( t_headers )

#     try:
#         r = requests.get( u, headers=headers, timeout=REQUEST_TIMEOUT, verify=False )
#     except Exception as e:
#         print( colored("[-] %s: %s" % (ip,e), 'red') )
#         return

#     if not 'Content-Type' in r.headers:
#         r.headers['Content-Type'] = ''

#     score = responseCompare( r_reference, r )

#     if score['average'] > GOOD_CANDIDATE_SCORE:
#         if is_cloudflare2( IPAddress(ip) ):
#             sys.stdout.write( colored("%s" % ip, 'yellow') )
#             sys.stdout.write( " is CloudFlare\n" )
#         else:
#             sys.stdout.write( colored("%s" % ip, 'green') )
#             sys.stdout.write( " is a GOOD candidate with an average similarity of %d%%\n" % score['average'] )
#     else:
#         sys.stdout.write( "%s" % ip )
#         sys.stdout.write( " is not a good candidate with an average similarity of %d%%\n" % score['average'] )

#     print( colored("Status=%d (%d%%), Length=%d (%d%%), Headers=%d (%d%%), Content-Type=%s (%d%%)" % (r.status_code,score['dist_status_code'],len(r.content),score['dist_content'],len(r.headers),score['dist_headers'],r.headers['Content-Type'],score['dist_content_type']), 'white') )


def testBypass3( t_multiproc, r_reference, host, ip ):
    sys.stdout.write( 'progress: %d/%d\r' %  (t_multiproc['n_current'],t_multiproc['n_total']) )
    t_multiproc['n_current'] = t_multiproc['n_current'] + 1

    if is_cloudflare4( IPAddress(ip) ):
        sys.stdout.write( colored("%s" % ip, 'yellow') )
        sys.stdout.write( " is CloudFlare\n" )
        return

    u = 'https://' + ip
    headers = {"Host":host}
    headers.update( t_headers )

    try:
        r = requests.get( u, headers=headers, timeout=REQUEST_TIMEOUT, verify=False )
    except Exception as e:
        print( colored("[-] %s: %s" % (ip,e), 'red') )
        return

    if not 'Content-Type' in r.headers:
        r.headers['Content-Type'] = ''

    score = responseCompare( r_reference, r )

    if score['average'] > GOOD_CANDIDATE_SCORE:
        sys.stdout.write( colored("%s" % ip, 'green') )
        sys.stdout.write( " is a GOOD candidate with an average similarity of %d%%\n" % score['average'] )
    else:
        sys.stdout.write( "%s" % ip )
        sys.stdout.write( " is not a good candidate with an average similarity of %d%%\n" % score['average'] )

    print( colored("Status=%d (%d%%), Length=%d (%d%%), Headers=%d (%d%%), Content-Type=%s (%d%%)" % (r.status_code,score['dist_status_code'],len(r.content),score['dist_content'],len(r.headers),score['dist_headers'],r.headers['Content-Type'],score['dist_content_type']), 'white') )


def responseCompare( r_reference, r ):
    score = {
        'dist_status_code': 0,
        'dist_content_type': 0,
        'dist_content': 0,
        'dist_headers': 0,
        'average': 0
    }

    if r.status_code == r_reference.status_code:
        score['status_code'] = 'OK'
        score['dist_status_code'] = 100
    else:
        score['status_code'] = 'NOK'
        score['dist_status_code'] = 0

    if len(r.headers['Content-Type']) > 0 and len(r_reference.headers['Content-Type']) > 0:
        dist = levenshtein( r.headers['Content-Type'], r_reference.headers['Content-Type'] )
        score['dist_content_type'] = 100 - ( dist*100 / len(r_reference.headers['Content-Type']) )
    else:
        if len(r.headers['Content-Type']) == 0 and len(r_reference.headers['Content-Type']) == 0:
            score['dist_content_type'] = 100
        else:
            score['dist_content_type'] = 0

    if len(r.content) > 0 and len(r_reference.content) > 0:
        dist = levenshtein( r.content[0:COMPARE_FIRST_CHARS], r_reference.content[0:COMPARE_FIRST_CHARS] )
        score['dist_content'] = 100 - ( dist*100 / len(r_reference.content[0:COMPARE_FIRST_CHARS]) )
    else:
        if len(r.content) == 0 and len(r_reference.content) == 0:
            score['dist_content'] = 100
        else:
            score['dist_content'] = 100 / (len(r.content)+len(r_reference.content))
    if score['dist_content'] < 0:
        score['dist_content'] = 0

    s_headers = ''
    s_reference_headers = ''
    t_sorted_keys = sorted( r_reference.headers )

    for k in t_sorted_keys:
        if not k in t_exclude_headers:
            s_reference_headers = s_reference_headers + k + '=' + r_reference.headers[k] + ';;'
            if k in r.headers:
                s_headers = s_headers + k + '=' + r.headers[k] + ';;'
            else:
                s_headers = s_headers + k + '=;;'

    # print( s_reference_headers )
    # print( s_headers )
    dist = levenshtein( s_headers, s_reference_headers )
    score['dist_headers'] = 100 - ( dist*100 / len(s_reference_headers) )

    # score['average'] = score['dist_status_code']*COEF_STATUS_CODE + score['dist_content_type']*COEF_CONTENT_TYPE + score['dist_content']*COEF_CONTENT + score['dist_headers']*COEF_HEADERS
    score['average'] = score['dist_status_code'] + score['dist_content_type'] + score['dist_content'] + score['dist_headers']
    score['average'] = score['average'] / 4;

    return score


if not url.startswith( 'http' ):
    url = 'https://'+url
t_url_parse = parse.urlparse( url )
# t_url_parse = urlparse( url )
t_host_parse = tldextract.extract( t_url_parse.netloc )
domain = host = t_host_parse.domain + '.' + t_host_parse.suffix
if len(t_host_parse.subdomain):
    host = t_host_parse.subdomain + '.' + host
# print( t_url_parse )
# print( t_host_parse )


t_ips = []
t_subs = []

for s in t_sources:
    if s != 'crtsh' and s != 'censys' and s != 'securitytrails':
        if not os.path.isfile( s ):
            print( colored("[-] source file not found: %s" % s, 'red') )
        else:
            readIPfromFile( domain, s )

if 'crtsh' in t_sources:
    grabber_crtsh( domain )

if 'censys' in t_sources:
    grabber_censys( domain )

if 'securitytrails' in t_sources:
    grabber_securitytrails( domain )

t_ips = set( t_ips )
t_ips_cloudflare = []
t_ips_notcloudflare = []
t_headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:56.0) Gecko/20100101 Firefox/56.0',
}

print( "[+] %d unique ips collected" % len(t_ips) )

if len(t_ips) == 0:
    exit()


print( "[+] Performing reference request..." )
try:
    r_reference = requests.get( url, timeout=3, verify=False, headers=t_headers )
    if not 'Content-Type' in r_reference.headers:
        r_reference.headers['Content-Type'] = ''
except Exception as e:
    print( colored("[-] error occured: %s" % e, 'red') )
    exit()

# print(r_reference.content)
# exit()
print( colored("Status=%d, Length=%d, Headers=%d, Content-Type=%s" % (r_reference.status_code,len(r_reference.content),len(r_reference.headers),r_reference.headers['Content-Type']), 'cyan') )
print( "[+] Testing bypass..." )


###################################### VERSION 3 ######################################

t_multiproc = {
    'n_current': 0,
    'n_total': len(t_ips)
}

pool = Pool( MAX_THREADS )
pool.map( partial(testBypass3,t_multiproc,r_reference,host), t_ips )
pool.close()
pool.join()

exit()


###################################### VERSION 2 ######################################

for ip in set(t_ips):
    if is_cloudflare2( IPAddress(ip) ):
        t_ips_cloudflare.append( ip )
        print( colored("%s" % ip, 'red') )
    else:
        t_ips_notcloudflare.append( ip )
        testBypass( r_reference, ip, host )

exit()


###################################### SLOW OLD VERSION ######################################

print( "[+] Checking Cloudflare... (cpu killer)" )

for ip in set(t_ips):
    if is_cloudflare( IPAddress(ip) ):
        t_ips_cloudflare.append( ip )
        print( colored("%s" % ip, 'white') )
    else:
        t_ips_notcloudflare.append( ip )
        print( "%s" % ip )

print( colored("[*] %d Cloudflare ips detected" % len(t_ips_cloudflare), 'white') )
# for ip in t_ips_cloudflare:
#     print( colored(ip,'white') )
print( colored("[+] %d ips not Cloudflare" % len(t_ips_notcloudflare), 'green') )
# for ip in t_ips_notcloudflare:
#     print( ip )

if TEST_BYPASS:
    print( "[+] Performing reference request..." )
    try:
        r_reference = requests.get( url, timeout=3, verify=False )
        if not 'Content-Type' in r_reference.headers:
            r_reference.headers['Content-Type'] = ''
    except Exception as e:
        print( colored("[-] error occured: %s" % e, 'red') )
        exit()
    print( colored("Status=%d, Length=%d, Headers=%d, Content-Type=%s" % (r_reference.status_code,len(r_reference.content),len(r_reference.headers),r_reference.headers['Content-Type']), 'cyan') )
    print( "[+] Testing bypass..." )
    t_threads = []
    for ip in t_ips_notcloudflare:
        testBypass( r_reference, ip, host )
