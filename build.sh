#!/bin/bash

function unit_tests {	
	find . -name '*_test.go' | while read file; do
		n=$(dirname -- "$file")
		echo "$n"
	    done | sort -u | while read d; do
		c=$(pwd)
		cd "$d"

		value=$(echo $d | grep -c "Godeps")
		if [ $value -eq 0 ]; then
			go test -i
			go test -p 1
		fi

		cd "$c"
	done
}

unit_tests