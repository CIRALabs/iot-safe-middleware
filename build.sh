#!/bin/bash

SCRIPTDIR="$( cd "$(dirname "$0")" ; pwd -P )"
BUILDDIR=${SCRIPTDIR}/Build

# We generate a "build" directory
mkdir -p ${BUILDDIR}
cd ${BUILDDIR}

# We run the cmake command first on the Thales project
mkdir -p thales
cd thales
cmake ${SCRIPTDIR}/cpp/iot-safe-middleware
make

# We now build our wrapper. Note that we pass the location
# of both libraries to our cmake command because the paths
# are quite complex
cd ..
cmake ${SCRIPTDIR}/cpp/c4amiddleware \
    -DGENERAL_LIB="${BUILDDIR}/thales/iotsafelib/general/libiotsafegeneral.so" \
    -DPLATFORM_LIB="${BUILDDIR}/thales/iotsafelib/platform/modem/libiotsafeplatform.so" \
    -DCOMMON_LIB="${BUILDDIR}/thales/iotsafelib/common/libiotsafecommon.so"
make

# Finally, we build the golang project
MAJOR=2
MINOR=1
MAINT=0
if [ -z "$BUILD_NUMBER" ] ; then
    BUILD_NUMBER=0
fi
BUILD_VERSION="$MAJOR"".""$MINOR"".""$MAINT"".""$BUILD_NUMBER"

export GOPATH="${SCRIPTDIR}/golang"

# Getting dependencies
go get github.com/op/go-logging
go get github.com/eclipse/paho.mqtt.golang

cd "${SCRIPTDIR}/golang/src/tlsdemo/cmd"
echo "[ INFO ] Building Golang application"
go build -ldflags "-X main.COMPILATION_DATE=`date -u +%D-%T` -X main.COMPILATION_VERSION=`echo $BUILD_VERSION`" -o tlsdemo
if [ $? -eq 0 ]; then
    echo "[ INFO ] Finished building project"
    # We now copy the binary to the Build directory for completeness (not really necessary)
    cp "${SCRIPTDIR}/golang/src/tlsdemo/cmd/tlsdemo" ${BUILDDIR}
fi

exit $?
