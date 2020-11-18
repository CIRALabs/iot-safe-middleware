#!/usr/bin/python3
#******************************************************************************#
# Title:       demo.py
# Author:      O. C.
# Project:     L-Spark Middleware Code for IoT devices
# Description: The current file provides a demo of some of the functions in the
#              middleware
#******************************************************************************#

import utils
import iot_mw as iot
from six import b

client_cert_pem = b("""-----BEGIN CERTIFICATE-----
MIIBljCCATugAwIBAgIUU0TrgDf2myPhjwFM7Ds+ftOmlGAwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUSW9UIFJlZ2lzdHJ5IFRFU1QgQ0EwIBcNMjAxMDAxMTc0MzA1
WhgPOTk5OTEyMzEyMzU5NTlaMDAxLjAsBgNVBAMMJTEuODkxMjIzMDIwMDAzMTA2
MDAwM0YuaW90cmVnaXN0cnkuY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATz
NnndT6EPqqBDZLLVno5S7XlYGBKJwG1RrXtBsX1VN291KAYHTRKE/QOZDmvc+L4X
kx2+XcHgH7dvLRhxnxefo0IwQDAfBgNVHSMEGDAWgBTYjzVgKM/9N3M54XDiBIqt
lnfxADAdBgNVHQ4EFgQUj/648DmAxqBcN5ebCz3F7xyokKkwCgYIKoZIzj0EAwID
SQAwRgIhANL8Tsy6NhSgCmxWP+GbxJfOXJQwxYgSYIDsgtrIrNsnAiEAlepXGuGG
jdngbVpqXEBXMkHb/ZeL3yQxmoolVIwQqEM=
-----END CERTIFICATE-----""")

sub_cert_pem = b("""-----BEGIN CERTIFICATE-----
MIIByTCCAW+gAwIBAgIUOBBOd6F4wGqeg/413bk2Htl6BEcwCgYIKoZIzj0EAwIw
JDEiMCAGA1UEAwwZSW9UIFJlZ2lzdHJ5IFRFU1QgUm9vdCBDQTAgFw0yMDA5MDIy
MDQzNDBaGA85OTk5MTIzMTIzNTk1OVowHzEdMBsGA1UEAwwUSW9UIFJlZ2lzdHJ5
IFRFU1QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATks8kEZp+tGP7YbHCc
gj/IKFwZzpmRouRtJwomxkuVHhd2/vIUxRgm6wt6nKsXroxbg7IyaW8TMlmY+HZL
RCsmo4GBMH8wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwGQYD
VR0RBBIwEIIOaW90cmVnaXN0cnkuY2EwHwYDVR0jBBgwFoAUCxI7Tlg60EjZ6syS
kqBKAlMFRMIwHQYDVR0OBBYEFNiPNWAoz/03cznhcOIEiq2Wd/EAMAoGCCqGSM49
BAMCA0gAMEUCIEUDF1NZzEnNQbDWstZuZJqqpW/ZN8y1dWXVY6mkCJvhAiEA5opq
MpnmAuEA9IPmwv+d/39M6JYA+rrT+5V6v3SMea4=
-----END CERTIFICATE-----""")

root_cert_pem = b("""-----BEGIN CERTIFICATE-----
MIIBrzCCAVWgAwIBAgIUZ8vuCIhJrWa2KUf29qqcann7piUwCgYIKoZIzj0EAwIw
JDEiMCAGA1UEAwwZSW9UIFJlZ2lzdHJ5IFRFU1QgUm9vdCBDQTAgFw0yMDA5MDIy
MDQzMzhaGA85OTk5MTIzMTIzNTk1OVowJDEiMCAGA1UEAwwZSW9UIFJlZ2lzdHJ5
IFRFU1QgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL1rOR1Yx0iT
Px5HJ2vmgMB6bX+HxoT980eBJSvhrFweLxHxxCdgpny+cvU/tmyPvcl8zMhYHpTt
tKxvNZ8fe8yjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB8G
A1UdIwQYMBaAFAsSO05YOtBI2erMkpKgSgJTBUTCMB0GA1UdDgQWBBQLEjtOWDrQ
SNnqzJKSoEoCUwVEwjAKBggqhkjOPQQDAgNIADBFAiEArrt4tnFDSotGIc5/v5/J
soSMB2U/Dtr/tN237j1iJiQCIExSs+89anMIUyAfZHroUnAeKeazyrqImSIzYm99
q1hT
-----END CERTIFICATE-----""")

# Just to make things a little prettier. This was taken from
# https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# We use this simple class to run the various tests
class TestCase:
    # Constructor of the class
    def __init__( self, name, callback, *args ):
        self.name     = name
        self.callback = callback
        self.args     = args

    def run_test(self):
        isSuccess = False
        try:
            retVal = self.callback(*self.args)

            # If the function returns false, it means that there was
            # an error, even though there might not be an exception that
            # was raised
            if not retVal == False:
                isSuccess = True
        except Exception as e:
            print(e)
        self.success = isSuccess

    def print_status(self):
        if self.success:
            print(f"{bcolors.OKGREEN}[ SUCCESS ]{bcolors.ENDC}" + " --> " + self.name )
        else:
            print(f"{bcolors.FAIL}[ FAILURE ]{bcolors.ENDC}" + " --> " + self.name )

TestArray = []
# This tests the validaton of the certificate
listOfCerts = [root_cert_pem, sub_cert_pem, client_cert_pem]

TestArray.append( TestCase(        \
    "Testing a certificate chain", \
    utils.validateCertChain,       \
    listOfCerts ) )

# We test the 'getRandom' function
TestArray.append( TestCase( \
    "Testing 'getRandom'",  \
    utils.getRandom,        \
    16 ) )

# We test the 'getFqdnAndPort' function
TestArray.append( TestCase(     \
    "Testing 'getFqdnAndPort'",  \
    utils.getFqdnAndPort  ) )

# We test the 'generateSignature', 'getCertificate' and
# 'verifySignature' functions at the same time. First, we
# define a function for this test. Essentially, we generate
# a signature and use a client certificate to see if the
# signature matches
def testSignatureAndVerification( Message ):
    Signature  = utils.generateSignature( Message.encode("utf-8") )
    ClientCert = utils.getCertificate(utils.CLIENT_CERTIFICATE_ID)

    isSuccess  = utils.verifySignatureWithCert( Message, Signature, ClientCert, "ecdsa_sha256" )
    if not isSuccess:
        raise Exception("Failed verification of the signature with the client certificate")

TestArray.append( TestCase(                                                 \
    "Testing 'generateSignature', 'getCertificate' and 'verifySignature'",  \
    testSignatureAndVerification,                                           \
    "Hello World" ) )

# This function corresponds to workdow initiated by the command "getAllInfo"
TestArray.append( TestCase(                 \
    "Testing 'getAllInfo' command",         \
    iot.getAllInfoCmd ))

# We initialize the C++ library (not necessary)
utils.init()

# We go through each test and we display the results
def run_tests():
    i = 1
    for test in TestArray:
        print("\n*************************************************")
        print("*               Performing test " + str(i) + "               *")
        print("*************************************************")
        test.run_test()
        test.print_status()
        print("\n")
        i += 1

# If we call the script directly from the command line, it will run all the tests
if __name__ == "__main__":
    run_tests()
