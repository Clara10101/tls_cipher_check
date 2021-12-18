import requests, json, argparse, re
import xml.etree.ElementTree as ET
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--host", help="host", type=str, required=True)
parser.add_argument("--port", help="port", type=int, required=False, default=443)
parser.add_argument("--report", help="report file name", type=str, required=False, default="nmap_ssl-enum-ciphers")
args = parser.parse_args()

#Argument verification
if not 1 <= args.port <= 65535:
    raise argparse.ArgumentTypeError("Invalid port number")

ValidIpAddressRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
ValidHostnameRegex = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
if not (re.match(ValidHostnameRegex, args.host) or re.match(ValidIpAddressRegex, args.host)):
    raise argparse.ArgumentTypeError("Invalid host name or IP address")

#Nmap scan - script ssl-enum-ciphers
nmap_cmd = "nmap -oX " + args.report + "_" + args.host + "_" + str(args.port) + ".xml --script ssl-enum-ciphers -p " + str(args.port) + " " + args.host
process = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE)
process.wait()

def check_security(cs):
    url = 'https://ciphersuite.info/api/cs/'
    headers = {'accept': 'application/json'}
    r = requests.get(url + cs, headers=headers)
    try:
        r_json = json.loads(r.text)
    except ValueError:
        return "No result"
    return r_json[cs]['security']

#Read xml report
tree = ET.parse(args.report + "_" + args.host + "_" + str(args.port) + ".xml")
root = tree.getroot()

#Possible protocols
ciphers = ['SSLv2','SSLv3','TLSv1.0','TLSv1.1','TLSv1.2','TLSv1.3']
for protocol in ciphers:
    for e in root.findall("./host/ports/port/script[@id='ssl-enum-ciphers']/table[@key='" + protocol + "']/table[@key='ciphers']/table/elem[@key='name']"):
        #Ciphersuite API check to verify security level
        print('{} - {} - {}'.format(protocol, e.text, check_security(e.text)))

