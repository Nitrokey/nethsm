#!/bin/sh

FILE=$1
TITLE=$2

OUT=$1.png

gnuplot <<EOF
reset
set terminal png
set output "$OUT"

set xlabel "uptime (in seconds)"
set autoscale

set style data lines

set y2tics
set ylabel "MB"
set y2label "op/s"

xmin = `sort -nk 1 $FILE | grep -v '#' | grep -v '^[[:space:]]*$' | head -n 1 | awk '{print $1}'`
total_http = `tail -n 1 $FILE | awk '{print $6}'`
total_kv = `tail -n 1 $FILE | awk '{print $7}'`

set title sprintf("Memory consumption ($TITLE, %i HTTP, %i KV write)", total_http, total_kv)

plot "$FILE" using (\$1 - xmin):(\$2 / (1024 * 1024)) title "gc", \
     "$FILE" using (\$1 - xmin):(\$3 / (1024 * 1024)) title "malloc", \
     "$FILE" using (\$1 - xmin):(\$6 / \$1) axes x1y2 title "http responses / sec", \
     "$FILE" using (\$1 - xmin):(\$7 / \$1) axes x1y2 title "kv write / sec"
EOF
#"$FILE" using (\$1 - xmin):(\$8 * 1000) title "response time"
