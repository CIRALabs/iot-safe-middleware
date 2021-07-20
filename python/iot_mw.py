#!/usr/bin/python3
#******************************************************************************#
# Title:       iot-mw.py
# Author:      O. C.
# Project:     L-Spark Middleware Code for IoT devices
# Description: The current file implements a command line handler for various
#              functionalities related to the IoT device middleware
#******************************************************************************#

import argparse
import base64

import getdns

import utils

#******************************************************************************#
# Parsing arguments
#******************************************************************************#

# General parser. The argument parser contains a description only. We add a subparser
# to it. That way, we can provide an individual parser for each command we might
# want to add.
parser = argparse.ArgumentParser(description="Command line tool to access the IoT device middleware.")
subparsers = parser.add_subparsers(help="To get help for a specific command, run './%(prog)s <command> --help'", dest="command")

# The following are general modifiers for the commands.
parser.add_argument('--port', action='store', type=str, dest='port', default=utils.MODEM_PORT, help="Port to which the modem is connected")
group = parser.add_mutually_exclusive_group()
group.add_argument('--debug',   action='store_true', dest='debug')
group.add_argument('--info',    action='store_true', dest='info')
group.add_argument('--notice',  action='store_true', dest='notice')
group.add_argument('--warning', action='store_true', dest='warning')
group.add_argument('--error',   action='store_true', dest='error')
group.add_argument('--cert',   action='store_true', dest='cert')


# The following are the different commands allowed.

# getPublicKeyCmd
getPublicKeyCmd = subparsers.add_parser('getPublicKey', help='Retrieves the public key of the IoT device')

# signCmd
signCmd = subparsers.add_parser('sign', help='Generates a signature on the SIM card')
signCmd.add_argument('--tbs', action='store', type=str, dest='tbs', required=True, help="Base64 encoded string of data to be signed")
signCmd.add_argument('--raw', action='store_true', dest='raw', default=False, help="If true, performs a raw signature (no hash)")

# getUrlAndPortCmd
getUrlAndPort = subparsers.add_parser('getUrlAndPort', help='Retrieves the URL and the port of the server endpoint')

# getAllInfo
getAllInfo = subparsers.add_parser('getAllInfo', help='Retrieves all the information required for establishing a TLS session and validates the cryptographic material provided by the SIM card')

# isProvisioned
isProvisioned = subparsers.add_parser('isProvisioned', help='Checks whether or not the SIM card has been provisioned.')

args = parser.parse_args()

#******************************************************************************#
# This is the actual "main" that will run
#******************************************************************************#

# We set the debug level first. Note that an error is given already if more than
# one of those is set (because we use a mutually exclusive group) and the default
# is already specified in utils (should be "INFO")
if args.debug:
    utils.CPP_LOG_LEVEL = utils.LOG_LEVEL_DEBUG
elif args.info:
    utils.CPP_LOG_LEVEL = utils.LOG_LEVEL_INFO
elif args.notice:
    utils.CPP_LOG_LEVEL = utils.LOG_LEVEL_NOTICE
elif args.warning:
    utils.CPP_LOG_LEVEL = utils.LOG_LEVEL_WARNING
elif args.error:
    utils.CPP_LOG_LEVEL = utils.LOG_LEVEL_ERROR

# We set the port
utils.MODEM_PORT = args.port

requestType = getdns.RRTYPE_CERT if args.cert else getdns.RRTYPE_TLSA

#******************************************************************************#
#  \brief Retrieves and validates all the necessary information from the SIM
#
# We define one function particularly complex that will be often called. This
# function will fetch all the required information from the SIM card and will
# make the necessary verifications in order to validate the content received.
#
# @return URL
# @return Port
# @return aspCert
# @return clientCert
#******************************************************************************#
def getAllInfoCmd():
    # We first retrieve a lot of information
    rootCert          = utils.getCertificate( utils.ROOT_CERTIFICATE_ID )
    subCert           = utils.getCertificate( utils.CIRA_SUB_CERTIFICATE_ID )
    clientCert        = utils.getCertificate( utils.CLIENT_CERTIFICATE_ID )
    aspCert           = utils.getCertificate( utils.ASP_CERTIFICATE_ID )
    endpointSignature = base64.b64encode( utils.readAsn1File( utils.SERVER_ENDPOINT_HASH_ID ) )
    aspCertSignature  = base64.b64encode( utils.readAsn1File( utils.SERVER_CERT_HASH_ID ) )
    URL, Port         = utils.getUrlAndPort( IsSecure=True ) # Check 2

    # Then we start making some verifications:
    # 1 - Validate that the rootCert is self-signed and that it signs the subCert and that
    #     the subCert signs the client cert.
    # 2 - Validate that the signature on the endpoint (Already done in getUrlAndPort)
    # 3 - Validate that the ASP certificate was signed by the subCert
    # 4 - Ensure that the client certificate is contained in the DNS's database

    # Check 1
    if not utils.validateCertChain( [rootCert, subCert, clientCert], isRootSelfSigned=True ):
        raise Exception("Couldn't validate the chain of certificates")
    else:
        utils.log( utils.LOG_LEVEL_NOTICE, "The certificate chain is valid")

    # Check 3
    if not utils.validateASPCert( aspCert, subCert, aspCertSignature, "ECDSA_SHA256" ):
        raise Exception("Couldn't validate the signature on the ASP certificate")
    else:
        utils.log( utils.LOG_LEVEL_NOTICE, "The signature on the ASP certificate is valid")

    # Check 4
    if not utils.validateDNSRecord(requestType, clientCert):
        raise Exception(f"Client {requestType} record wasn't found in the DNS server")
    else:
        utils.log(utils.LOG_LEVEL_NOTICE,
                  f"The {requestType} for {utils.getCNFromCert(clientCert)} is matching the certificate")

    return URL, Port, aspCert, clientCert

if __name__ == "__main__":
    if args.command == None:
        # If no arguments were given, we simply print the help menu
        parser.print_help()

    elif args.command == 'getAllInfo':
        # If you don't know what to run, run this command. It retrieves all the
        # information from the SIM card and perform the required verification to
        # ensure that everthing is signed properly. If no errors were encountered,
        # then the values are all returned.
        utils.init()

        # We fetch the information
        URL, Port, aspCert, clientCert = getAllInfoCmd()

        # Once all the checks have been successfully completed, we return the information
        print("", flush=True)
        print("URL: " + URL )
        print("Port: " + str(Port))
        print("ClientCert: " + clientCert.decode("utf-8").replace("\n",""))
        print("AspCert: " + aspCert.decode("utf-8").replace("\n",""))

    elif args.command == "sign":
        # For the signature, we start by checking the input TBS. The user must pass
        # a base64 encoded signature (to avoid any confusion).
        ToBeSigned = base64.b64decode( args.tbs )

        utils.init()
        Signature = None
        if args.raw:
            Signature = utils.generateRawSignature(ToBeSigned)
        else:
            Signature = utils.generateSignature(ToBeSigned)
        print("", flush=True)
        print("Signature: " + Signature.decode("utf-8"))

    elif args.command == "getPublicKey":
        utils.init()
        ClientCertificate = utils.getCertificate(utils.CLIENT_CERTIFICATE_ID)
        print("", flush=True)
        print("PublicKey: " + utils.extractPubKeyFromCert(ClientCertificate).decode("utf-8").replace("\n",""))

    elif args.command == "getUrlAndPort":
        utils.init()
        URL, Port = utils.getUrlAndPort()
        print("", flush=True)
        print("URL: " + URL)
        print("Port: " + str(Port))

    elif args.command == "isProvisioned":
        # Thales recommended to just check if we get some errors when running
        # the command to read the client certificate. This is not ideal as
        # there might be other reasons why there is an error, but for now it
        # can work.
        utils.init()
        try:
            utils.getCertificate( utils.CLIENT_CERTIFICATE_ID )
            print("", flush=True)
            print("IsProvisioned: true")
        except:
            print("", flush=True)
            print("IsProvisioned: false")

    # Success
    exit(0)
