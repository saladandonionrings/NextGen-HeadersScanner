import argparse
import requests
import pyfiglet
import json
import colored, cprint
from cprint import *
import time
from Wappalyzer import Wappalyzer, WebPage

'''
GLOBAL VARIABLES
'''
h=['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options', 'Referrer-Policy', 'X-XSS-Protection']
list=[]

'''
ARGS
'''
def get_args():
    parser = argparse.ArgumentParser(
        description='')
    parser.add_argument(
        '-u', '--url', type=str, help='target URL', required=True)
    args = parser.parse_args()
    URL = args.url
    return URL

url = get_args()

servers=['Apache', 'Nginx', 'IIS', 'Cloudflare', 'lighttpd']
reco = [
    ["Apache","X-Frame-Options", "https://tecadmin.net/configure-x-frame-options-apache/"],
    ["Apache","Strict-Transport-Security", "https://www.xolphin.com/support/Apache_FAQ/Apache_-_Configuring_HTTP_Strict_Transport_Security"],
    ["Apache","Content-Security-Policy", "https://content-security-policy.com/"],
    ["Apache","X-Content-Type-Options", "https://geekflare.com/secure-mime-types-in-apache-nginx-with-x-content-type-options/"],
    ["Apache","Referrer-Policy", "https://docs.nesez.com/2020/07/how-can-i-add-referrer-policy-header-in.html"],
    ["Apache","X-XSS-Protection", "https://webdock.io/en/docs/how-guides/security-guides/how-to-configure-security-headers-in-nginx-and-apache#3.-x-xss-protection"],
    ["nginx","X-Frame-Options", "https://fedingo.com/how-to-configure-x-frame-options-for-nginx/"],
    ["nginx","Strict-Transport-Security", "https://www.nginx.com/blog/http-strict-transport-security-hsts-and-nginx/"],
    ["nginx","Content-Security-Policy", "https://content-security-policy.com/examples/nginx/"],
    ["nginx","X-Content-Type-Options", "https://geekflare.com/secure-mime-types-in-apache-nginx-with-x-content-type-options/"],
    ["nginx","Referrer-Policy", "https://collinmbarrett.com/referrer-policy-header-nginx/"],
    ["nginx","X-XSS-Protection", "https://webdock.io/en/docs/how-guides/security-guides/how-to-configure-security-headers-in-nginx-and-apache#3.-x-xss-protection"],
    ["IIS","X-Frame-Options", "https://support.microsoft.com/en-us/office/mitigating-framesniffing-with-the-x-frame-options-header-1911411b-b51e-49fd-9441-e8301dcdcd79"],
    ["IIS","Strict-Transport-Security", "https://techexpert.tips/iis/enable-hsts-iis/"],
    ["IIS","Content-Security-Policy", "https://content-security-policy.com/"],
    ["IIS","X-Content-Type-Options", "https://docs.oracle.com/en/industries/health-sciences/argus-insight/8.2.1/aiscq/configure-x-content-type-options-iis.html"],
    ["IIS","Referrer-Policy", "TODO"],
    ["IIS","X-XSS-Protection", "TODO"],
    ["cloudflare","X-Frame-Options","https://developers.cloudflare.com/workers/examples/security-headers"],
    ["cloudflare","Strict-Transport-Security","https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security"],
    ["cloudflare","Content-Security-Policy","https://developers.cloudflare.com/fundamentals/get-started/reference/content-security-policies/"],
    ["cloudflare","X-Content-Type-Options","https://developers.cloudflare.com/workers/examples/security-headers"],
    ["cloudflare","Referrer-Policy","https://developers.cloudflare.com/workers/examples/security-headers"],
    ["cloudflare","X-XSS-Protection","https://developers.cloudflare.com/workers/examples/security-headers"],
    ["lighttpd","Strict-Transport-Security","https://www.cyberciti.biz/faq/lighttpd-setup-hsts-http-strict-transport-security/"]
    
    
]

bad=[]

resp=requests.get(url)
headers=resp.headers

'''
HEADER
'''
print("\033[3;35m")
header2 = pyfiglet.figlet_format("HTTP Security Header Scanner", font = "cybermedium")
print(header2)
server=headers.get('Server')
print("\033[1;35m\nWeb Server is :",server)

'''
wappalyzer = Wappalyzer.latest()
WebPage(url).info()
'''
'''
GOOD PRACTICES
'''
time.sleep(2)
print("\033[1;32m\n--- GOOD PRACTICES ---\n")
for i in h:
    if i in headers.keys():
        print("\033[1;32m{0} implemented with options :".format(i))
        print("\033[3;39m{}\n".format(headers.get(i)))
    else:
        list.append("{}".format(i))


'''
BAD PRACTICES
'''
time.sleep(2)
print("\033[1;30m--------------------------------------------------------------------------------------------\n")
print("\033[1;31m--- BAD PRACTICES ---\n")
for i in list:
    if i=="X-Frame-Options":
        print("No X-Frame-Options detected\nImplement it like that :\n X-Frame-Options: DENY | SAMEORIGIN | ALLOW-FROM URL\n---")
        bad.append(i)
    if i=="Content-Security-Policy":
        print("\nNo Content-Security-Policy detected\nImplement it like that :\n Content-Security-Policy: &lt;policy-directive&gt;; &lt;policy-directive&gt;\n---")
        bad.append(i)
    if i=="Strict-Transport-Security":
        print("\nNo Strict-Transport-Security detected\nImplement it like that :\n Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n---")
        bad.append(i)
    if i=="X-Content-Type-Options":
        print("\nNo X-Content-Type-Options detected\nImplement it like that :\n X-Content-Type-Options: nosniff\n---")
        bad.append(i)
    if i=="Referrer-Policy":
        print("\nNo Referrer-Policy detected\nImplement it like that :\n Referrer-Policy: no-referrer\n---")
        bad.append(i)
    if i=="X-XSS-Protection":
        print("\nNo X-XSS-Protection detected\nImplement it like that :\n X-XSS-Protection: 1; mode=block; report=https://domain.tld/folder/file.ext\n")
        bad.append(i)
        
'''
RECOMMENDATIONS
'''
time.sleep(2)       
print("\033[1;30m--------------------------------------------------------------------------------------------\n")
print("\033[1;32m--- RECOMMENDATIONS ---\n")

if server in servers:
    for serv,header,link in reco:
        if serv == server:
            if header in bad:
                cprint.info(header, " : ", link, "\n")
else:
    print("Web Server not supported")

        
