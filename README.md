# D2O Log4j Scanner
A Direct To Origin Log4j scanner

The script takes a list of Ips and Domains in ```10.10.10.10,Domain.com|Domain.com|Domain.com``` format. It iterates over each domain, obfuscation type and payload to send each bypass to every domain a IP serves a cert for.
 

### Usage:

```
usage: D2OLog4j.py [-h] (-f INPUT_FILE | -u INPUT_URL) [-ut URL_TARGET] [-ud URL_DOMAIN] [-ua USERAGENT] -c CALLBACK [-d] [-v] [--exclude-ua]

optional arguments:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --file INPUT_FILE
                        Input file. Should be in two columns. Ip,domain|domain|domain\n format.
  -u INPUT_URL, --url INPUT_URL
                        Test against a single URL (-ut/--url-target required as well)
  -ut URL_TARGET, --url-target URL_TARGET
                        If testing a single url, this is required to specify the target IP of the request, -u/--url required.
  -ud URL_DOMAIN, --url-domain URL_DOMAIN
                        If testing a single url, this is required to specify the target domain of the request, -u/--url required.
  -ua USERAGENT, --useragent USERAGENT
                        Specify the user agent
  -c CALLBACK, --callback CALLBACK
                        Request Callback
  -d, --dry-run         Run it with making requests to ensure it will generate the requests correctly.
  -v, --verbose         Show info like headers
  --exclude-ua          Exclude user agent from fuzzing.
```

Use namp "ssl-cert" script to find domains served for a IP.

I used sed to process that to a list that has the output of ```10.10.10.10,Domain.com|Domain.com|Domain.com``` format to pass to the script.

```
echo $(cat nmap_output.txt) | sed -E "s/Nmap scan report for /,\n/g" | sed -E 's/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) .*(\sSubject Alternative Name\:.+)(\s|\sIssuer:.+)/\1\2/g' | sed -E "s/,//g" | sed -E "s/(\s\|$)//g" | sed -E "s/(Subject\sAlternative\sName\:\s|DNS:)//g" | sed -E "s/Host is up.+/No-Domains-Returned/g" | sed -E "s/\s/\|/g" | sed -E "s/([0-9])\|([a-zA-Z]|\*)/\1,\2/g" > dto_list.txt
```
