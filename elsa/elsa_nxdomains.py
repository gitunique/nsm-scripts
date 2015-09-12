import sys
import json

#
# sh /opt/elsa/contrib/securityonion/contrib/cli.sh 'BRO_DNS.return_code=NXDOMAIN -BRO_DNS.query_type=PTR start:"2015-09-08T00:00" limit:10000'
#

# read json from stdin

values = json.load(sys.stdin) 
results = {}
for answer in values['results']:
    if answer['_fields'][3]['value'] in results.keys():
        if not ('sophosxl.net' in answer['_fields'][8]['value'] or 'malware.hash.cymru.com' in answer['_fields'][8]['value']):
            results[answer['_fields'][3]['value']].add(answer['_fields'][8]['value'])
    else:
        if not ('sophosxl.net' in answer['_fields'][8]['value'] or 'malware.hash.cymru.com' in answer['_fields'][8]['value']):
            results[answer['_fields'][3]['value']] = set()
            results[answer['_fields'][3]['value']].add(answer['_fields'][8]['value'])

for item in results.items():
    print("="*16)
    print(item[0])
    print("="*16)
    for v in item[1]:
        print "\t",v  
