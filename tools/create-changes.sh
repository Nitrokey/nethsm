#!/bin/sh

first=$(grep ^# $1 | head -1)
second=$(grep ^# $1 | head -2 | tail -1)
sed -ne "/$first/,/$second/p" $1 | grep -v "$second"

