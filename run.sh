#!/bin/bash

SCRIPTDIR="$( cd "$(dirname "$0")" ; pwd -P )"

if [[ -z "${BUILD_DIR}" ]]; then
  source "${SCRIPTDIR}/setenv.sh"
fi

cd ${SCRIPTDIR}/golang/src/tlsdemo/cmd
./tlsdemo --debug demo
