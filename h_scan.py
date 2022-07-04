import argparse
import requests
import pyfiglet
import json
import colored, cprint
from cprint import *
import time
import webtech
import pandas as pd



'''
GLOBAL VARIABLES
'''
h=['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options', 'Referrer-Policy', 'X-Permitted-Cross-Domain-Policies', 'Clear-Site-Data', 'Cross-Origin-Embedder-Policy','Cross-Origin-Ressource-Policy']
bh=['X-XSS-Protection','Expect-CT','Public-Key-Pins']
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
    ["Apache","X-Permitted-Cross-Domain-Policies", "https://stackoverflow.com/questions/29150384/how-to-allow-cross-domain-request-in-apache2"],
    ["Apache","Clear-Site-Data", "https://www.geeksforgeeks.org/http-headers-clear-site-data"],
    ["Apache", "Cross-Origin-Embedder-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"],
    ["Apache", "Cross-Origin-Ressource-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)"],
    ["Apache", "Cache-Control", "https://www.howtogeek.com/devops/how-to-configure-cache-control-headers-in-apache/"],
    ["nginx","X-Frame-Options", "https://fedingo.com/how-to-configure-x-frame-options-for-nginx/"],
    ["nginx","Strict-Transport-Security", "https://www.nginx.com/blog/http-strict-transport-security-hsts-and-nginx/"],
    ["nginx","Content-Security-Policy", "https://content-security-policy.com/examples/nginx/"],
    ["nginx","X-Content-Type-Options", "https://geekflare.com/secure-mime-types-in-apache-nginx-with-x-content-type-options/"],
    ["nginx","Referrer-Policy", "https://collinmbarrett.com/referrer-policy-header-nginx/"],
    ["nginx","X-Permitted-Cross-Domain-Policies", "https://themewizz.com/2021/08/24/x-permitted-cross-domain-policies/#nginx"],
    ["nginx","Clear-Site-Data", "https://www.geeksforgeeks.org/http-headers-clear-site-data"],
    ["nginx", "Cross-Origin-Embedder-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"],
    ["nginx", "Cross-Origin-Ressource-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)"],
    ["nginx", "Cache-Control", "https://www.howtogeek.com/devops/how-to-configure-cache-control-headers-in-nginx/"],
    ["IIS","X-Frame-Options", "https://support.microsoft.com/en-us/office/mitigating-framesniffing-with-the-x-frame-options-header-1911411b-b51e-49fd-9441-e8301dcdcd79"],
    ["IIS","Strict-Transport-Security", "https://techexpert.tips/iis/enable-hsts-iis/"],
    ["IIS","Content-Security-Policy", "https://content-security-policy.com/"],
    ["IIS","X-Content-Type-Options", "https://docs.oracle.com/en/industries/health-sciences/argus-insight/8.2.1/aiscq/configure-x-content-type-options-iis.html"],
    ["IIS","Referrer-Policy", "https://owasp.org/www-project-secure-headers/#referrer-policy"],
    ["IIS","X-Permitted-Cross-Domain-Policies", "https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies"],
    ["IIS","Clear-Site-Data", "https://www.geeksforgeeks.org/http-headers-clear-site-data"],
    ["IIS", "Cross-Origin-Embedder-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"],
    ["IIS", "Cross-Origin-Ressource-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)"],
    ["IIS", "Cache-Control", "https://serverfault.com/questions/285328/iis-cache-control-header-settings"],
    ["cloudflare","X-Frame-Options","https://developers.cloudflare.com/workers/examples/security-headers"],
    ["cloudflare","Strict-Transport-Security","https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security"],
    ["cloudflare","Content-Security-Policy","https://developers.cloudflare.com/fundamentals/get-started/reference/content-security-policies/"],
    ["cloudflare","X-Content-Type-Options","https://developers.cloudflare.com/workers/examples/security-headers"],
    ["cloudflare","Referrer-Policy","https://developers.cloudflare.com/workers/examples/security-headers"],
    ["cloudflare","X-Permitted-Cross-Domain-Policies","https://developers.cloudflare.com/workers/examples/security-headers"],
    ["cloudflare","Clear-Site-Data", "https://www.geeksforgeeks.org/http-headers-clear-site-data"],
    ["cloudflare", "Cross-Origin-Embedder-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"],
    ["cloudflare", "Cross-Origin-Ressource-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)"],
    ["cloudflare", "Cache-Control", "https://teknikaldomain.me/post/cloudflare-cache-control/"],
    ["lighttpd","Strict-Transport-Security","https://www.cyberciti.biz/faq/lighttpd-setup-hsts-http-strict-transport-security/"]
    
    
]

bad=[]

resp=requests.get(url)
headers=resp.headers

'''
HEADER
'''
print("\033[1;35m")
header2 = pyfiglet.figlet_format("Security Headers Scanner", font = "cybermedium")
print(header2)
server=headers.get('Server')
print("\033[1;35m\nWeb Server is :",server)

wt = webtech.WebTech(options={'json': True})
char=['"','[',']','{','}','version: null','name: ',',']

try:
    report = wt.start_from_url(url)
    d=json.dumps(report, indent=4, sort_keys=True)
    for i in char:
        if i in d:
            d=d.replace(i, '')
    
    print("\n\033[1;33mIdentified technologies:\n", d)

except webtech.utils.ConnectionException:
    print("Connection error")
    
'''
GOOD PRACTICES
'''
obso_h=[]
time.sleep(2)
print("\033[1;32m\n--- GOOD PRACTICES ---\n")
for i in h:
    if i in headers.keys():
        print("\033[1;32m{0} implemented with options :".format(i))
        print("\033[3;39m{}\n".format(headers.get(i)))

    else:
        list.append("{}".format(i))
        
for y in bh:
    if y in headers.keys():
        obso_h.append("{}".format(y))


'''
BAD PRACTICES
'''
time.sleep(2)
print("\033[1;30m--------------------------------------------------------------------------------------------\n")
cprint("\033[1;31m--- BAD PRACTICES ---\n")
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
    if i=="X-Permitted-Cross-Domain-Policies":
        print("\nNo X-Permitted-Cross-Domain-Policies detected\nImplement it like that :\n X-Permitted-Cross-Domain-Policies: none | master-only | by-content-type | by-ftp-filename | all\n---")
        bad.append(i)
    if i=="Clear-Site-Data":
        print("\nNo Clear-Site-Data detected\nImplement it like that :\n Clear-Site-Data: 'cache','cookies','storage'\n---")
        bad.append(i)
    if i=="Cross-Origin-Embedder-Policy":
        print("\nNo Cross-Origin-Embedder-Policy detected\nImplement it like that :\n Cross-Origin-Embedder-Policy: require-corp\n---")
        bad.append(i)
    if i=="Cross-Origin-Ressource-Policy":
        print("\nNo Cross-Origin-Ressource-Policy detected\nImplement it like that :\n Cross-Origin-Resource-Policy: same-origin\n---")
        bad.append(i)

for y in obso_h:
    if i=="X-XSS-Protection":
        print("\nX-XSS-Protection detected\nThis header has been deprecated by modern browsers and its use can introduce additional security issues on the client side. Use CSP instead.\n")
        bad.append(i)
    if i=="Expect-CT":
        print("\nExpect-CT detected\nIt is obsolete since June 2021.\n")
        bad.append(i)
    if i=="Public-Key-Pins":
        print("\nPublic-Key-Pins detected\nThis header has been deprecated by all major browsers and is no longer recommended. Avoid using it, and update existing code if possible.\n")
'''
RECOMMENDATIONS
'''
time.sleep(2)       
print("\033[1;30m--------------------------------------------------------------------------------------------\n")
print("\033[1;32m--- RECOMMENDATIONS ---\n")

for serv,header,link in reco:
    if serv in server:
        if header in bad:
            cprint.info(header, " : ", link, "\n")
