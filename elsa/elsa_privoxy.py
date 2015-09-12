import sys
import json

# sh /opt/elsa/contrib/securityonion/contrib/cli.sh 'BRO_HTTP.status_code=403 groupby:site limit:10000'
# read json from stdin

data = json.load(sys.stdin) 
for site in data['results']['site']:
    print("{0}\t{1}".format(site['_count'],site['_groupby']))
