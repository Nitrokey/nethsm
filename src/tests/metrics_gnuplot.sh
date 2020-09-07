#!/bin/sh

tmp=$(date +%s)

echo "output to $tmp"

echo "# statistics gathered in tab-separated columns:" >> $tmp
echo "# 'uptime' 'gc major' 'malloc allocated' 'gc major collections' 'http responses' 'kv write' 'http response time' " > $tmp

while true; do
    curl -s --insecure https://metrics:MetricsMetrics@192.168.1.1/api/v1/metrics |
        jq --raw-output '[ .uptime, ."gc_major_bytes", ."total allocated space", ."gc_major_collections", ."http response total", ."kv write", ."http response time" ] | @csv' | sed -e 's/"//g' | sed -e 's/,/\t/g' >> $tmp;
    sleep 1
done
