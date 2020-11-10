#!/bin/bash
# Generated on Tue Sep 29 12:00:19 EDT 2020

#
# This script can be called to setup the environment variables
# and PATH so that it is easier to use the SPA software.
#
# Call this script using the DOT notation:
# . /.../setenv.sh
#
# Or, source it:
# source /.../setenv.sh
#

if [ "$0" = "$BASH_SOURCE" ]; then
	echo "You should run this script using 'source'"
	exit 1
fi
SCRIPTDIR="$( cd "$(dirname "$BASH_SOURCE")" ; pwd -P )"

# We export the build directory so that Python knows where
# to access the C++ library and Golang knows where to access
# the Python library.
export BUILD_DIR="${SCRIPTDIR}"

# Paths
if [[ -z "$PATH" ]]; then
    export PATH=${SCRIPTDIR}/python
    export PATH=${SCRIPTDIR}/golang/src/tlsdemo/cmd
else
    export PATH=$PATH:${SCRIPTDIR}/python
    export PATH=$PATH:${SCRIPTDIR}/golang/src/tlsdemo/cmd
fi
