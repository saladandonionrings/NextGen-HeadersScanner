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
        description='Python Headers Scanner')
    parser.add_argument(
        '-u', '--url', type=str, help='target URL', required=True)
    args = parser.parse_args()
    URL = args.url
    return URL

url = get_args()

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
print("\033[1;30m--------------------------------------------------------------------------------------------\n")
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
        print("No X-Frame-Options detected\n---")
        bad.append(i)
    if i=="Content-Security-Policy":
        print("\nNo Content-Security-Policy detected\n---")
        bad.append(i)
    if i=="Strict-Transport-Security":
        print("\nNo Strict-Transport-Security detected\n---")
        bad.append(i)
    if i=="X-Content-Type-Options":
        print("\nNo X-Content-Type-Options detected\n---")
        bad.append(i)
    if i=="Referrer-Policy":
        print("\nNo Referrer-Policy detected\n---")
        bad.append(i)
    if i=="X-Permitted-Cross-Domain-Policies":
        print("\nNo X-Permitted-Cross-Domain-Policies detected\n---")
        bad.append(i)
    if i=="Clear-Site-Data":
        print("\nNo Clear-Site-Data detected\n---")
        bad.append(i)
    if i=="Cross-Origin-Embedder-Policy":
        print("\nNo Cross-Origin-Embedder-Policy detected\n---")
        bad.append(i)
    if i=="Cross-Origin-Ressource-Policy":
        print("\nNo Cross-Origin-Ressource-Policy detected\n---")
        bad.append(i)
        
time.sleep(2)
print("\033[1;30m--------------------------------------------------------------------------------------------\n")
cprint("\033[1;33m--- DEPRECATED HEADERS IDENTIFIED ---\n")
x=["x-xss-protection","X-xss-protection","X-XSS-Protection","X-XSS-Protection"]
e=["expect-ct","EXPECT-CT","Expect-ct","Expect-CT"]
p=["Public-Key-Pins","public-key-pins", "Public-key-pins", "PUBLIC-KEY-PINS"]
for z in obso_h:
    if z in x:
        print("\nX-XSS-Protection detected\n--> This header has been deprecated by modern browsers and its use can introduce additional security issues on the client side.\n--> Use CSP instead.\n")
        bad.append(i)
    if z in e:
        print("\nExpect-CT detected\n--> It is obsolete since June 2021.\n")
        bad.append(i)
    if z in p:
        print("\nPublic-Key-Pins detected\n--> This header has been deprecated by all major browsers and is no longer recommended.\n--> Avoid using it, and update existing code if possible.\n")
        
print("\033[1;31m---[!] END---")
