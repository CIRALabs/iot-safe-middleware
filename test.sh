#!/bin/bash

SCRIPTDIR="$( cd "$(dirname "$0")" ; pwd -P )"

PORT="/dev/ttyUSB0"

cd ${SCRIPTDIR}/python

if [ ! -z "$1" ]; then
    PORT=$1
fi

# We test the python script for the demo
./demo.py --port $PORT
exit 0
