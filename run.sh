#!/bin/bash

SCRIPTDIR="$( cd "$(dirname "$0")" ; pwd -P )"

PORT="/dev/ttyUSB0"

if [[ -z "${BUILD_DIR}" ]]; then
  source "${SCRIPTDIR}/setenv.sh"
fi

if [ ! -z "$1" ]; then
    PORT=$1
fi

cd ${SCRIPTDIR}/golang/src/tlsdemo/cmd
./tlsdemo --debug --port $PORT demo
