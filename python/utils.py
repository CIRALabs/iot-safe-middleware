#******************************************************************************#
# Title:       utils.py
# Author:      O. C.
# Project:     L-Spark Middleware Code for IoT devices
# Description: The current file provides various functions that can be used in
#              the middleware aplication
# Functions:
#   - validateDNSRecord
#   - getCertDigestFromServer
#   - getCertDigestLocal
#   - getCNFromCert
#   - getCertContent
#   - validateCertChain
#   - getHashFromAlg
#   - validateASPCert
#   - verifySignatureWithCert
#   - convertBase64ToPem
#   - convertPemToBase64
#   - extractPubKeyFromCert
#   - getRandom
#   - readAsn1File
#   - getCertificate
#   - getUrlAndPort
#   - verifyUrlAndPort
#   - generateSignature
#   - generateRawSignature
#   - init
#******************************************************************************#

import base64
import ctypes
import hashlib
import json
import os
import pprint
from datetime import datetime

import ecdsa
import getdns
import numpy as np
from OpenSSL import crypto
from ecdsa.util import sigdecode_der

# The following paths might be updated in the future. Note that the buildDir
# environment variable is set with setenv.sh and allows Python, C++ and Golang
# to know where the respective binaries are set.
buildDir = None
try:
    buildDir = os.environ["BUILD_DIR"]
except:
    currentDir = os.path.dirname( os.path.abspath(__file__) )
    buildDir   = os.path.join( currentDir, ".." )

LIB_PATH_C4A_MIDDLEWARE   = os.path.join(
                            buildDir,
                            "Build/cpp_wrapper/libc4amiddleware.so" )

# We import the C++ library
common   = ctypes.CDLL(LIB_PATH_C4A_MIDDLEWARE)

# This value is used to access the DNS. Additional entries can be provided, but
# the format must be respected as it matches that of the "getdns" library
DNS_ADDR = [{'address_type': 'IPv4', 'address_data': '149.112.121.10'},
            {'address_type': 'IPv4', 'address_data': '149.112.122.10'}]


# Through experimentation, we noticed that zeros were returned when asking
# for more than 127 bytes of entropy through the getRandom function (i.e.,
# asking for 128 bytes or more). To avoid unwanted and potentially dangerous
# behaviour, we limit the number of bytes of entropy to 127 for the getRandom
# function.
MAX_BUFFER_SIZE = 128

# Define maximum size expected when reading from the file system
MAX_FILE_SIZE     = 2048
MAX_SIZE_CERT     = 2048
MAX_SIZE_URL_PORT = 100

# We define a maximum size of an ECDSA SHA256 signature. An ECDSA signature is up to 2
# times the number of bytes of the hash (2 x 32) plus 6 bytes used for DER encoding.
# Therefore, the maximum possible is 72 bytes.
MAX_ECDSA_SIGN_SIZE = 72
HASH_SIZE           = 32

# The following variables are error codes that corresond to those in the C++ wrapper. Note
# that they are currently unused since the C++ wrapper already outputs detailed error
# messages.
ERROR_OK                  = 0
ERR_NO_CONNECT_PY         = 1
ERR_GENERAL_PY            = 2
ERR_GENERATING_SIG_PY     = 3
ERR_INVALID_PARAMETERS_PY = 4
ERR_ENCODING_SIG_PY       = 5
ERR_NOT_ENOUGH_MEMORY_PY  = 6
ERR_BAD_FORMAT_PY         = 7

# Different log levels are allowed for the C++ code
LOG_LEVEL_DEBUG   = 0
LOG_LEVEL_INFO    = 1
LOG_LEVEL_NOTICE  = 2
LOG_LEVEL_WARNING = 3
LOG_LEVEL_ERROR   = 4

# Modify this variable to change the log level. By default, it is LOG_LEVEL_INFO
CPP_LOG_LEVEL = LOG_LEVEL_INFO

# This part is used to configure the port that will be used to communicate with
# the modem. You can modify this string based on your connection with the modem.
MODEM_PORT = "/dev/ttyUSB0"

# This is just for esthetic purposes and defines how many PEM characters wide a
# certificate will be.
CERT_WIDTH = 64

# The following labels are used to parse the port and URL from the JSON string
# saved in the SIM.
URL_LABEL  = "url"
PORT_LABEL = "port"

# The following constants are used to retrieve files. These numbers
# are based on the container IDs provided in the documentation
# CLIENT_PRIVATE_KEY_ID    = 1 -> Not accessible
CLIENT_CERTIFICATE_ID      = 2
ASP_CERTIFICATE_ID         = 3
# EPHEMERAL_PRIVATE_KEY_ID = 4 -> Not accessible
# EPHEMERAL_PUBLIC_KEY_ID  = 5 -> Needs to be generated (not planning on implementing that yet)
ROOT_CERTIFICATE_ID        = 6
CIRA_SUB_CERTIFICATE_ID    = 7
SERVER_ENDPOINT_ID         = 8  # Retrieved with the function "getUrlAndPort"
SERVER_ENDPOINT_HASH_ID    = 9
SERVER_CERT_HASH_ID        = 10

# We dress up a list of the certificates. This way, the function "getCertificate" in
# Python can parse the file appropriately as a certificate if given one of those IDs
# and we can return an error otherwise
LIST_OF_CERTS = [CLIENT_CERTIFICATE_ID,  \
                 ASP_CERTIFICATE_ID,     \
                 ROOT_CERTIFICATE_ID,    \
                 CIRA_SUB_CERTIFICATE_ID]

# Here, we dress a list of the ASN.1 encoded values, which should correspond to all
# accessible files except for the SERVER_ENDPOINT_ID. The reason why we do this is
# to point to a C++ function that expects an ASN.1 encoded value. It shouldn't be
# critical, but it allows the C++ function to pass the length of the file, allowing
# the Python code to properly parse the received file.
LIST_OF_ASN1_FILES = LIST_OF_CERTS + [SERVER_ENDPOINT_HASH_ID, SERVER_CERT_HASH_ID]

# Implementing a cheap logger for now.
def log( Level, Input ):
    Prefix = ""
    if Level >= CPP_LOG_LEVEL:
        if Level == LOG_LEVEL_DEBUG:
            Prefix = "[ DEBUG ] "
        elif Level == LOG_LEVEL_INFO:
            Prefix = "[ INFO ] "
        elif Level == LOG_LEVEL_NOTICE:
            Prefix = "[ NOTICE ] "
        elif Level == LOG_LEVEL_WARNING:
            Prefix = "[ WARNING ] "
        elif Level == LOG_LEVEL_ERROR:
            Prefix = "[ ERROR ] "
        else:
            return
        print(Prefix, end='')
        print(Input)



#------------------------------- DNSSEC Utils ---------------------------------#
# The following functions provide some DNSSEC related functions.



#******************************************************************************#
#  \brief Validates that a certificate is in a DNS's database
#
# Implements DNSSEC over TLS to check whether or not the certificate is contained
# in the database of the server
#
# @param CertificatePem PEM formatted certificate to check
# @return True if the certificate chain is valid and raises an exception otherwise
#******************************************************************************#
def validateDNSRecord(requestType, certPem):

    # We assume that the common name of the certificate is the query name
    queryName = getCNFromCert( certPem )

    # We define a set of extensions
    extensions = {
        "dnssec_return_only_secure": getdns.EXTENSION_TRUE, # Will only return verified entries
        "add_warning_for_bad_dns"  : getdns.EXTENSION_TRUE, # FIXME: Not sure if necessary
        "return_both_v4_and_v6"    : getdns.EXTENSION_TRUE, # Handles IPv4 and IPv6
    }

    # We start filling up the context for our query. This context will always be
    # the same in our use case as we only want to ensure that the certificate is
    # in the DNS's database
    ctx = getdns.Context()
    ctx.dns_root_servers   = DNS_ADDR
    ctx.tls_authentication = getdns.AUTHENTICATION_REQUIRED

    # We perform the query itself
    results = ctx.general( name = queryName, request_type = requestType, extensions = extensions )
    if results.status != getdns.RESPSTATUS_GOOD:
        raise Exception("Error during DNSSEC query: " + str(results.status))

    if CPP_LOG_LEVEL <= LOG_LEVEL_DEBUG:
        # This might be too verbose, even for debug mode...
        pprint.pprint(results.replies_full)

    # We use a for loop here, but there should only be two entries, one for the
    # RRSIG, which we don't need to check as it's already checked by getdns. We
    # check the other one though
    for item in results.replies_tree[0]['answer']:
        if item['type'] == requestType:
            # We perform the digest of the certificate using the same algorithm
            # as the one used by the server
            digestOfCertLocal = getCertDigestLocal( certPem, item )

            # We now extract and properly decode the digest of the certificate
            # obtained from the DNSSEC server
            if getdns.RRTYPE_CERT:
                digestOfCertServer = getCertDigestFromServerCert(item)
            elif getdns.RRTYPE_CERT:
                digestOfCertServer = getCertDigestFromServerTlsa(item)
            else:
                raise Exception("Unsupported RRTYPE can not decode digest from record")


            # Both values should now be equal. Otherwise, we express both as a
            # hex sequence to help debugging.
            if digestOfCertLocal != digestOfCertServer:
                print("Computed digest: " + digestOfCertLocal.hex())
                print("Digest from DNS: " + digestOfCertServer.hex())
                raise Exception("The digest of the client certificate doesn't match the DNSSEC record")
            else:
                log( LOG_LEVEL_NOTICE, "Certificate with CN '" + queryName + "' was validated by the DNSSEC" )
                return True

    # Shouldn't reach this point
    return False

#******************************************************************************#
#  \brief Extracts digest of certificate from DNSSEC answer
#
# The encoding of the digest of the certificate contained in the DNSSEC server
# should be a base64 string. TODO: Add a verification check to verify the length
# of the hash to ensure it matches the algorithm used. However, this can't be
# done yet because this standard still need to be added. Adding this verifiation
# could help provide a more useful debugging message (the error might be in the
# encoding of the DNS answer).
#
# @param DnssecAnswer   Answer of the DNSSEC containing the hash of the certificate
# @return Decoded hash object
#******************************************************************************#
def getCertDigestFromServerCert(DnssecAnswer):
    return DnssecAnswer['rdata']['certificate_or_crl'].tobytes()


def getCertDigestFromServerTlsa(DnssecAnswer):
    return DnssecAnswer['rdata']['certificate_association_data'].tobytes()

#******************************************************************************#
#  \brief Gets the digest of a certificate's content
#
# A new standard will need to be defined to retrieve the appropriate hash
# algorithm from the DNSSEC answer. In the mean time, we will simply be
# using SHA256 as a hard-coded value. This is why the interface for this function
# already takes the DNSSEC answer into account
#
# @param CertPem        Certificate represented as a string
# @param DnssecAnswer   Answer of the DNSSEC containing (not yet), the hash algorithm
# @return Appropriate hash object
#******************************************************************************#
def getCertDigestLocal( CertPem, DnssecAnswer ):
    hashAlg      = hashlib.sha256
    digestOfCert = hashAlg( getCertContent( CertPem ) )
    return digestOfCert.digest()



#------------------------------- Crypto Utils ---------------------------------#
# The following functions provide some cryptographic functions.



#******************************************************************************#
#  \brief Retrieves the common name from a certificate
#
# @param CertPem    Byte array containing the PEM formatted certificate
# @return String containing the common name.
#******************************************************************************#
def getCNFromCert( CertPem ):
    # We retrieve the subject's components from the certificate
    x509Cert = crypto.load_certificate( crypto.FILETYPE_PEM, CertPem )
    SubjectComponents = x509Cert.get_subject().get_components()

    # We search for the common name entry
    for component in SubjectComponents:
        if component[0] == b"CN":
            return component[1].decode("utf-8")
    raise Exception("Couldn't get the common name from the certificate")

#******************************************************************************#
#  \brief Returns the bytes content of a PEM encoded certifiate
#
# @param CertPem    Byte array containing the PEM formatted certificate
# @return Bytes containing the actual content of the certificate
#******************************************************************************#
def getCertContent( CertPem ):
    # We remove the first and last lines of the certificate and isolate the content
    CertStr = ""
    CertLines = CertPem.decode('utf-8').splitlines()
    for i in range(len(CertLines)):
        # We skip the "begin" and the "end"
        if i == 0 or i == len(CertLines) - 1:
            continue
        CertStr += CertLines[i]

    return base64.b64decode(CertStr)

#******************************************************************************#
#  \brief Validates a certificate chain
#
# Provided a list of certificates, this function validates them and ensure that
# the list is ok.
#
# @param listOfCerts    String of PEM-encoded certificates. The first certificate
#                       is assumed to be the root certificate and the last one is
#                       assumed to be the certificate at the bottom of the chain.
# @param isRootSelfSigned Key word argument (True by default) that checks if the
#                         first certificate in the list is self-signed.
# @return True if the certificate chain is valid and false otherwise
#******************************************************************************#
def validateCertChain( listOfCerts, isRootSelfSigned=True ):
    isChainValid = True

    # We return an error if the list provied is empty
    if len(listOfCerts) == 0:
        raise Exception("The list of certificates must be non-empty")

    # We prepare an X509 store. Since we're validating a chain and starting with
    # the root certificate, it doesn't matter whether we put the following
    # statement within the loop or outside the loop.
    store = crypto.X509Store()

    # For the first certificate in the chain, we make sure that it is a self-signed
    # certificate. Note that more explanations are provided below for each command
    if isRootSelfSigned:
        rootCert = crypto.load_certificate( crypto.FILETYPE_PEM, listOfCerts[0] )
        store.add_cert( rootCert )
        storeCtx = crypto.X509StoreContext( store, rootCert )
        try:
            storeCtx.verify_certificate()
        except Exception as e:
            log( LOG_LEVEL_ERROR, e )
            return False

    # We subsequently load each certificate in our store
    for i in range( len(listOfCerts) - 1 ):
        # We load the certificate in the store. Since certificate i is assumed to
        # sign certificate i+1, we will treat the current certificate as the CA
        caCert = crypto.load_certificate( crypto.FILETYPE_PEM, listOfCerts[i] )
        store.add_cert( caCert )

        # We now load the certificate i+1 (tbv = to be verified). Note that the
        # loop stops at len(listOfCerts) - 1, so we don't have to worry about
        # overflowing the list of certs
        tbvCert = crypto.load_certificate( crypto.FILETYPE_PEM, listOfCerts[i+1])

        # We check whether or not the certificate is valid based on our store
        storeCtx = crypto.X509StoreContext( store, tbvCert )

        # If the certificate is not valid, an exception is raised. We'll convert
        # that into a bool instead
        try:
            storeCtx.verify_certificate()
        except Exception as e:
            log( LOG_LEVEL_ERROR, e )
            isChainValid = False
            break

    return isChainValid

#******************************************************************************#
#  \brief Returns the proper hash object based on the name of the algorithm
#
# @param algorithm    Name of an algorithm. Currently supports only "ECDSA_SHA384"
#                     and "ECDSA_SHA256" (case insensitive).
# @return Appropriate hash object
#******************************************************************************#
def getHashFromAlg( algorithm ):
    if algorithm.lower() == "ecdsa_sha384":
        return hashlib.sha384
    elif algorithm.lower() == "ecdsa_sha256":
        return hashlib.sha256

#******************************************************************************#
#  \brief Validate ASP certificate
#
# Because this certificate was not issued by the IoT sub-cert, we must use an
# unconventional way to test the signature. Indeed, within the eSIM, there is
# a signature of the hash of the ASP certificate that was made using the IoT
# sub-cert private key. We therefore check the various fields in the ASP
# certificate to ensure it's valid, but we complete by validating the signature
# on the hash of the certificate.
#
# @param aspCertPem   ASP certificate loaded during the manufacturing process.
#                     Note that this certificate is not issued by the IoT sub-cert
#                     but there is a signature of the hash of the certificate that
#                     was signed by the IoT sub-cert private key and that must be
#                     validated
# @param iotCertPem   Certificate of the IoT device. We use the public key to
#                     validate the signature of the aspCert
# @param signature    Signature of the hash of the aspCert made by the iotCert's
#                     associated private key
# @param algorithm    Algorithm used for the signature. Note that this algorithm
#                     is not necessarily the same as the one contained in the
#                     certificate.
# @return True if the certificate chain is valid and false otherwise
#******************************************************************************#
def validateASPCert( aspCertPem, iotCertPem, signature, algorithm ):
    # We start by checking the asp Certificate. We want to check the "notBefore"
    # and "notAfter" fields to ensure that the certificate is still valid
    aspCert = crypto.load_certificate( crypto.FILETYPE_PEM, aspCertPem )

    # We retrieve the "notAfter" and "notBefore" fields to see if the certificate
    # is still valid. Note that we must convert the time in the appropriate
    # format to be used by the "datetime" module
    notBefore = datetime.strptime( aspCert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ' )
    notAfter  = datetime.strptime( aspCert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ' )

    # We raise exceptions if the dates are not appropriate
    if datetime.utcnow() > notAfter:
        raise Exception("The certificate has expired")
    elif datetime.utcnow() < notBefore:
        raise Exception("The certificate is not valid yet")

    # Before we pass the ASP certificate to the verifying function, we need to trim
    # the PEM header as well as the newlines.
    aspCertPem = convertPemToBase64( aspCertPem )

    return verifySignatureWithCert( aspCertPem, signature, iotCertPem, algorithm )

#******************************************************************************#
#  \brief Verifies a signature using a certificate
#
# This function takes a message, a signature, a certificate and an algorithm. We
# extract the public key from the certificate, hash the message based on the hash
# specified in the algorithm and we validate the signature with it. Note that we
# currently only support ECDSA signatures.
#
# @param Message        String or bytes containing the incoming message to validate
# @param Signature      String or bytes containing the signature
# @param CertificatePem PEM encoded string or bytes containing the certificate. The
#                       public key is extracted to verify the signature
# @param algorithm      Algorithm used for the signature.
# @return True if the certificate chain is valid and false otherwise
#******************************************************************************#
def verifySignatureWithCert( Message, Signature, CertificatePem, algorithm ):

    # We verify the inputs
    if isinstance( Message, str ):
        Message = Message.encode("utf-8")
    elif not isinstance( Message, bytes ):
        raise Exception("The input must be a string or an array of bytes")
    if isinstance( Signature, str ):
        Signature = Signature.encode("utf-8")
    elif not isinstance( Signature, bytes ):
        raise Exception("The input must be a string or an array of bytes")
    if isinstance( CertificatePem, str ):
        CertificatePem = CertificatePem.encode("utf-8")
    elif not isinstance( CertificatePem, bytes ):
        raise Exception("The input must be a string or an array of bytes")

    # We start by extracting the public key from the certificate
    PublicKeyStr = extractPubKeyFromCert( CertificatePem )

    # We create a verification key object
    # TODO: Check for something similar with RSA
    PublicKey = ecdsa.VerifyingKey.from_pem( PublicKeyStr, hashfunc=getHashFromAlg( algorithm ) )

    # We convert the bytes signature into an hex representation
    Signature = bytes.fromhex( base64.b64decode( Signature ).hex() )

    # We verify the signature using the public key. Note that we return a boolean
    # instead of raising an exception
    try:
        PublicKey.verify( Signature, Message, sigdecode = sigdecode_der )
        return True
    except Exception as e:
        log( LOG_LEVEL_ERROR, e )
        return False

#******************************************************************************#
#  \brief We convert a base64 string to a PEM formatted string
#
# Note that this function was quickly written for development purposes and could
# be improved in several ways. First, there are no checks on the "BeginStr" and
# "EndStr" inputs. The ideal way would be to properly parse the data to see what
# object we are dealing with and set the appropriate header/footer. However, this
# would take quite a bit of time. After a quick research on Internet and a little
# bit of effort, I couldn't use the "crypto.load_certificate" function or another
# from the x509 library. Those functions should however exist. In any case, this
# should be sufficient for the time being.
#
# @param CertString  String containing the certificate content
# @param BeginStr    String used in the beginning of the PEM file (e.g., "CERTIFICATE")
# @param EndStr      Similar as BeginStr, but for the end of the PEM file.
# @return Byte array containing the PEM encoded value
#******************************************************************************#
def convertBase64ToPem(CertString, BeginStr, EndStr):
    # We write the header for the certificate
    NewString = b"-----BEGIN " + BeginStr.encode("utf-8") + b"-----\n"

    # We split the certificate string to add "\n" every 64 characters
    SpacedCert = [CertString[i:i + CERT_WIDTH] for i in range( 0, len(CertString), CERT_WIDTH )]

    for line in SpacedCert:
        NewString = NewString + line + b"\n"

    # We finally add the last part
    NewString = NewString + b"-----END " + EndStr.encode("utf-8") + b"-----"
    return NewString

#******************************************************************************#
#  \brief We convert a PEM string to a base64 formatted string
#
# Similar comments as the ones for the analoguous function "convertBase64ToPem"
# apply here also. However, this conversion is easier to do because we have to
# remove the first and last line regardless of what it is
#
# @param PemString  String containing the certificate content
# @return Byte array containing the base64 encoded value
#******************************************************************************#
def convertPemToBase64( PemString ):
    lines = PemString.decode("utf-8").splitlines()

    # We remove the first and last line and we concatenate all other lines while
    # removing line feeds
    NewString = ""
    for line in lines[1:len(lines)-1]:
        NewString += line

    return base64.b64decode( NewString.encode("utf-8") )

#******************************************************************************#
#  \brief Extracts a public key from a certificate
#
# This function takes a certificate and extracts the public key as a base64
# encoded string.
#
# @param CertificatePem  String or byte array containing PEM encoded certificate
# @return String containing the public key in base64 encoding.
#******************************************************************************#
def extractPubKeyFromCert(CertificatePem):
    # Checking inputs
    if isinstance( CertificatePem, str ):
        CertificatePem = CertificatePem.encode("utf-8")
    elif not isinstance( CertificatePem, bytes ):
        raise Exception("The input must be a string or an array of bytes")

    # We load the certificate in order to extract the public key
    Certificate  = crypto.load_certificate( crypto.FILETYPE_PEM, CertificatePem )
    PublicKey    = Certificate.get_pubkey()

    # We return the public key as a PEM encoded string
    return crypto.dump_publickey( crypto.FILETYPE_PEM, PublicKey )



#-------------------------- Access to C++ Library -----------------------------#
# The following functions contain hooks into the C++ library to access the SIM.



#******************************************************************************#
#  \brief Gets random data from the eSIM
#
# We fetch entropy from the eSIM. Note that there is a limit on the size of the
# buffer we can return. If the limit is exceeded, we raise an exception. Later
# on, it would be a good idea to have an additional wrapper to handle longer
# buffer (we could simply break it down in chunks and concatenate all the chunks).
# However, I do not believe that this is necessary at this time.
#
# @param Length   Length of the data to be returned
# @return Array of random integers fetched from the SIM card
#******************************************************************************#
def getRandom( Length ):
    # We check the inputs
    if not isinstance( Length, int ):
        raise Exception("The input must be an integer")
    elif Length >= MAX_BUFFER_SIZE:
        raise Exception("Cannot return more than " + str(Length) + " bytes at once")

    # We prepare the values for retrieving entropy
    uDataLen  = ctypes.c_uint16( Length )
    pData     = ( ctypes.c_uint8 * Length )()
    uLogLevel = ctypes.c_uint8( CPP_LOG_LEVEL )
    pPort     = MODEM_PORT.encode("utf-8")

    # We run the command
    Response = common.GetRandom( pData, uDataLen, pPort, uLogLevel )
    if Response != ERROR_OK:
        raise Exception("Error while running function: " + str(Response) )

    # We cast the returned value to an array of ints (each int represents a byte)
    ReturnArray = []
    for element in list(pData):
        ReturnArray.append( element )

    return ReturnArray

#******************************************************************************#
#  \brief Reads an ASN.1 encoded file on the eSIM by container ID
#
# We fetch an ASN.1 encoded file associated to the ID provided. Note that
# there is currently no way to get a list of the containers and their content, so
# we rely entirely on the available documentation.
#
# @param ContainerId    Integer identifying the container. Values allowed range
#                       between 1 and 10 inclusively. (e.g., 2)
# @return Byte array containing the file's content
#******************************************************************************#
def readAsn1File( ContainerId ):

    # We verify the inputs provided
    if not isinstance( ContainerId, int ):
        raise Exception("The container ID must be an integer")
    elif not ContainerId in LIST_OF_ASN1_FILES:
        raise Exception("The container ID provided does not correspond to an ASN.1 file")

    # We prepare the values for retrieving the certificate
    u32ContainerId = ctypes.c_uint32( ContainerId )
    u16BufferSize  = ctypes.c_uint16( MAX_FILE_SIZE )
    uContentArray  = ( ctypes.c_uint8 * MAX_FILE_SIZE )()
    uContentLen    = ctypes.pointer( ctypes.c_uint16( ) )
    uLogLevel      = ctypes.c_uint8( CPP_LOG_LEVEL )
    pPort          = MODEM_PORT.encode("utf-8")

    # We run the command
    Response = common.GetCertificate( u32ContainerId, u16BufferSize, uContentArray, uContentLen, pPort, uLogLevel )
    if Response != ERROR_OK:
        raise Exception("Error while running function: " + str(Response) )

    # We cast the returned value to an array of ints (each int represents a byte)
    ReturnArray = []
    for i in range( min(MAX_FILE_SIZE, uContentLen.contents.value) ):
        ReturnArray.append( uContentArray[i] )

    # We convert the array of integers into bytes.
    byteContent = np.array( ReturnArray, dtype=np.uint8 ).tobytes()

    return byteContent

#******************************************************************************#
#  \brief Gets certificate from eSIM by container ID
#
# We fetch a certificate associated to the containerID provided. Note that
# there is currently no way to get a list of the containers and their content, so
# we rely entirely on the available documentation.
#
# @param ContainerId    Integer identifying the container. Values allowed should
#                       fall within the "LIST_OF_CERTS" array (e.g., 2)
# @return Parsed certificate in a byte array
#******************************************************************************#
def getCertificate( ContainerId ):

    # We verify the inputs
    if not isinstance( ContainerId, int ):
        raise Exception("The container ID must be an integer")
    elif not ContainerId in LIST_OF_CERTS:
        raise Exception("The container ID provided does not correspond to a certificate")

    # We read the file and we convert it to a PEM encoded certificate
    certBytes = readAsn1File( ContainerId )
    pemCert   = convertBase64ToPem( base64.b64encode( certBytes ), "CERTIFICATE", "CERTIFICATE" )

    return pemCert

#******************************************************************************#
#  \brief Gets URL and Port from eSIM
#
# We fetch the URL and the port from the SIM card. Since there is only one
# containerId that is associated to this value, we don't need to pass it. Note that
# the URL and port are provided in a single JSON file inside the SIM card. The
# content of the file is as follows:
# {
#   "url": <url>,
#   "port": <port>
# }
# Since encoding of JSON string can lead to confusion, the verification of the
# signature of the URL and Port is done within this function if 'IsSecure' is true
#
# @param IsSecure  Keyword argument (True by default) which validates the signature
#                  on the URL and Port if set
# @return URL  string
# @return Port string
#******************************************************************************#
def getUrlAndPort( IsSecure=True ):

    # We prepare the values for retrieving the certificate
    uJsonStrArray  = ( ctypes.c_uint8 * MAX_SIZE_URL_PORT )()
    uJsonStrLen    = ctypes.pointer( ctypes.c_uint16( ) )
    uLogLevel      = ctypes.c_uint8( CPP_LOG_LEVEL )
    pPort          = MODEM_PORT.encode("utf-8")

    # We run the command
    Response = common.GetURLAndPort( uJsonStrArray, uJsonStrLen, pPort, uLogLevel )
    if Response != ERROR_OK:
        raise Exception("Error while running function: " + str(Response) )

    # We cast the returned value to an array of ints (each int represents a byte)
    ReturnArray = []
    for i in range( min(MAX_SIZE_URL_PORT, uJsonStrLen.contents.value) ):
        ReturnArray.append( uJsonStrArray[i] )

    # We convert the array of integers into a base64 string. This requires a few
    # conversion steps
    byteUrlAndPort = np.array( ReturnArray, dtype=np.uint8 ).tobytes()
    jsonString = byteUrlAndPort.decode("utf-8")

    # We check to see if we can verify the signature of the endpoint.
    if IsSecure:
        if not verifyUrlAndPort( jsonString ):
            raise Exception("Invalid URL and port number")
        elif CPP_LOG_LEVEL <= LOG_LEVEL_NOTICE:
            # Note that we could make this logging better at the Python level
            log( LOG_LEVEL_NOTICE, "The signature on the URL and port number is valid")

    # We transform the string into a JSON object
    jsonObject = json.loads( jsonString )
    URL        = jsonObject[URL_LABEL]
    Port       = jsonObject[PORT_LABEL]

    return URL, Port

#******************************************************************************#
#  \brief Verifies that the hash of the URL and port indeed matches the signature
#
# We need to retrieve the signature and a certificate from the SIM card to verify
# that the hash of the endpoint is valid.
#
# @return URL  string
# @return Port string
#******************************************************************************#
def verifyUrlAndPort( UrlAndPort ):

    # We retrieve the signature and the certificate stored on the SIM card
    endpointSignature = base64.b64encode( readAsn1File( SERVER_ENDPOINT_HASH_ID ) )
    ciraSubCert       = getCertificate( CIRA_SUB_CERTIFICATE_ID )

    # We now check the signature
    return verifySignatureWithCert( UrlAndPort, endpointSignature, ciraSubCert, "ECDSA_SHA256" )

#******************************************************************************#
#  \brief Generates a signature on the SIM card and returns it
#
# This function passes a message to the SIM card which will perform a SHA2-256
# hash of it and sign the message. Currently, there is no other supported
# algorithm than ECDSA-SHA256.
#
# @param Message  Either a string or a string of bytes. The array is treated
#                 as a base64 encoded value.
# @return Value of the signature (DER encoded)
#******************************************************************************#
def generateSignature( Message ):

    # We encode the message
    if isinstance( Message, str ):
        Message = base64.b64encode( Message )
    elif not isinstance( Message, bytes ):
        raise Exception("The input must be a string or an array of bytes")

    # Not sure how to initialize this function as it takes an array of a specific
    # length. So we provide the arguments and return types. Note that the "+1" to
    # the length is to include the null character to terminate the string
    common.GenerateSignature.argtypes = ( ctypes.c_char * (1 + len(Message)) ),   \
                                        ctypes.c_uint16,                          \
                                        ( ctypes.c_uint8 * MAX_ECDSA_SIGN_SIZE ), \
                                        ctypes.POINTER( ctypes.c_uint16 ),        \
                                        ctypes.c_char_p,                          \
                                        ctypes.c_uint8
    common.GenerateSignature.restypes = ctypes.c_int

    # We prepare the values for retrieving the certificate
    pMessage     = ctypes.create_string_buffer( Message )
    uMessageLen  = ctypes.c_uint16( len(pMessage) )

    # Only SHA256 signatures are supported by the eSIM. So currently, we hardcode
    # the length of the signature that is sent back. Note that the signature has
    # two 256-bit values and is ASN.1 encoded. The length should therefore not
    # exceed 72 bytes.
    pSignature  = ( ctypes.c_uint8 * MAX_ECDSA_SIGN_SIZE )()
    pu16SignLen = ctypes.pointer( ctypes.c_uint16() );
    uLogLevel   = ctypes.c_uint8( CPP_LOG_LEVEL )
    pPort       = MODEM_PORT.encode("utf-8")

    # We run the command
    Response = common.GenerateSignature( pMessage, uMessageLen, pSignature, pu16SignLen, pPort, uLogLevel )
    if Response != ERROR_OK:
        raise Exception("Error while running function: " + str(Response) )

    # We cast the returned value to an array of ints (each int represents a byte)
    ReturnArray = []
    for i in range(pu16SignLen.contents.value):
        ReturnArray.append( pSignature[i] )

    # We convert the array of integers into a base64 string. This requires a few
    # conversion steps
    byteCert = np.array( ReturnArray, dtype=np.uint8 ).tobytes()
    return base64.b64encode( byteCert )

#******************************************************************************#
#  \brief Generates a raw signature on the SIM card and returns it
#
# This function passes a message to the SIM card which will perform a raw
# signature. Currently, there is no other supported ECDSA 256
#
# @param Message  Either a string or a string of bytes. The array is treated
#                 as a base64 encoded value.
# @return Value of the signature (DER encoded)
#******************************************************************************#
def generateRawSignature( Message ):

    # We encode the message
    if isinstance( Message, str ):
        Message = base64.b64encode( Message )
    elif not isinstance( Message, bytes ):
        raise Exception("The input must be a string or an array of bytes")

    # Not sure how to initialize this function as it takes an array of a specific
    # length. So we provide the arguments and return types. Note that the "+1" to
    # the length is to include the null character to terminate the string
    common.GenerateRawSignature.argtypes = ( ctypes.c_char * (1 + len(Message)) ),   \
                                           ctypes.c_uint16,                          \
                                           ( ctypes.c_uint8 * MAX_ECDSA_SIGN_SIZE ), \
                                           ctypes.POINTER( ctypes.c_uint16 ),        \
                                           ctypes.c_char_p,                          \
                                           ctypes.c_uint8
    common.GenerateRawSignature.restypes = ctypes.c_int

    # We prepare the values for retrieving the certificate
    pMessage     = ctypes.create_string_buffer( Message )
    uMessageLen  = ctypes.c_uint16( len(pMessage) )

    # Only SHA256 signatures are supported by the eSIM. So currently, we hardcode
    # the length of the signature that is sent back. Note that the signature has
    # two 256-bit values and is ASN.1 encoded. The length should therefore not
    # exceed 72 bytes.
    pSignature  = ( ctypes.c_uint8 * MAX_ECDSA_SIGN_SIZE )()
    pu16SignLen = ctypes.pointer( ctypes.c_uint16() );
    uLogLevel   = ctypes.c_uint8( CPP_LOG_LEVEL )
    pPort       = MODEM_PORT.encode("utf-8")

    # We run the command
    Response = common.GenerateRawSignature( pMessage, uMessageLen, pSignature, pu16SignLen, pPort, uLogLevel )
    if Response != ERROR_OK:
        raise Exception("Error while running function: " + str(Response) )

    # We cast the returned value to an array of ints (each int represents a byte)
    ReturnArray = []
    for i in range(pu16SignLen.contents.value):
        ReturnArray.append( pSignature[i] )

    # We convert the array of integers into a base64 string. This requires a few
    # conversion steps
    byteCert = np.array( ReturnArray, dtype=np.uint8 ).tobytes()
    return base64.b64encode( byteCert )

#******************************************************************************#
#  \brief Initialization
#
# Currently, we only state the types of the arguments and the returned values.
# Note that not running this function doesn't seem to have any consequences
# however. Also, note that the "GenerateSignature" (C++) function is defined in
# the "generateSignature" function (Python) because of the variable length of the
# message.
#******************************************************************************#
def init( ):
    # GetRandom
    common.GetRandom.argtypes = ctypes.POINTER( ctypes.c_uint8 ), ctypes.c_uint16, ctypes.c_char_p, ctypes.c_uint8
    common.GetRandom.restypes = ctypes.c_int

    # GetCertificate
    common.GetCertificate.argtypes = ctypes.c_uint32,                                   \
                                     ctypes.c_uint16,                                   \
                                     ( ctypes.c_uint8 * MAX_SIZE_CERT ),                \
                                     ctypes.POINTER( ctypes.c_uint16 ),                 \
                                     ctypes.c_char_p,                                   \
                                     ctypes.c_uint8
    common.GetCertificate.restypes = ctypes.c_int

    # GetUrlAndPort
    common.GetURLAndPort.argtypes  = ( ctypes.c_uint8 * MAX_SIZE_URL_PORT ),            \
                                     ctypes.POINTER( ctypes.c_uint16 ),                 \
                                     ctypes.c_char_p,                                   \
                                     ctypes.c_uint8
    common.GetCertificate.restypes = ctypes.c_int
