#!/bin/bash

find . -name '*_test.go' | while read file; do
	n=$(dirname -- "$file")
	echo "$n"
    done | sort -u | while read d; do
	c=$(pwd)
	cd "$d"

	if [ "$d" != *"Godeps"* ]; then
		go test -i
		go test -p 1
	fi

	cd "$c"
done
