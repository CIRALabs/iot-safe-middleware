#!/bin/bash

SCRIPTDIR="$( cd "$(dirname "$0")" ; pwd -P )"

cd ${SCRIPTDIR}/python

# We test the python script for the demo
./demo.py
exit 0
