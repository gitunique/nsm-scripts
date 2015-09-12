import sys
import json

# read json from stdin
#
#  sh /opt/elsa/contrib/securityonion/contrib/cli.sh 'class=BRO_CONN BRO_CONN.dstport=80'
#

values = json.load(sys.stdin) 
results = {}
for answer in values['results']:
    if answer['_fields'][3]['value'] in results.keys():
        if not ('sophosxl.net' in answer['_fields'][5]['value'] or 'malware.hash.cymru.com' in answer['_fields'][5]['value']):
            results[answer['_fields'][3]['value']].add(answer['_fields'][5]['value'])
    else:
        if not ('sophosxl.net' in answer['_fields'][5]['value'] or 'malware.hash.cymru.com' in answer['_fields'][5]['value']):
            results[answer['_fields'][3]['value']] = set()
            results[answer['_fields'][3]['value']].add(answer['_fields'][5]['value'])

for item in results.items():
    print("="*16)
    print(item[0])
    print("="*16)
    for v in item[1]:
        print "\t",v  
