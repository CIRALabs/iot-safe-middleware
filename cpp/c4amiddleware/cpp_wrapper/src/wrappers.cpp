/*
 *    Copyright (c) 2019 - 2020, Thales DIS Singapore, Inc
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <iostream>
#include "ROT.h"
#include "GenericModem.h"
#include "sim-access-util.h"
#include "openssl-util.h"
#include "wrappers.h"
#include "common.h"


// Declaration of a couple static functions that are useful for development
static PY_ERR DumpMessage(
    unsigned char* pMsg,
    char* pBufferName,
    unsigned uOffset,
    unsigned uMsgLength );
static PY_ERR GetJsonStringLen(
    unsigned char* pJsonString,
    uint16_t u16MaxLen,
    uint16_t *pu16StringLen );
static PY_ERR GetAsn1LenFromOctetString(
    uint8_t *pu8Asn1Buffer,
    uint16_t *pu16Len );

// We define some global constants that will be initialized
static GenericModem modem;
static ROT* _py_ROT = NULL;

// The following function is used to initialize a configuration and return a pointer
// to a ROT.
PY_ERR _init(const char* pModemPort, uint8_t u8LogLevel) {
    PY_ERR Response = ERR_OK_PY;

    // We set the log level
    initLogLevel( u8LogLevel );

    // We open a connection with the modem port
    if(!modem.open(pModemPort)) {
        _log(PY_LOG_LEVEL_ERROR, "Error modem not found!");
        Response = ERR_NO_CONNECT_PY;
    }

    // We initialize the modem
    if(Response == ERR_OK_PY) {
       _py_ROT = new ROT();
       _py_ROT->init(&modem);
    }

    // We select the applet
    if(Response == ERR_OK_PY && !_py_ROT->select(false)) {
        _log(PY_LOG_LEVEL_ERROR, "Error: cannot select applet!");
        Response = ERR_NO_CONNECT_PY;
    }

    if(Response == ERR_OK_PY) {
        _log(PY_LOG_LEVEL_DEBUG, "Finished initialization of modem");
        return Response;
    } else {
        _log(PY_LOG_LEVEL_ERROR, "Failed initialization of modem");
        throw Response;
    }
}

// The following function is used to close the connection with the modem
// Note that we can't use the function given in sim-access-util.cpp because
// it uses a static variable for the modem and we don't have the same one here.
void _cleanup(GenericModem *pModem)
{
    delete _py_ROT;
    pModem->close();
    pModem = NULL;
}

// The following is used whenever there is an error during the execution of a call.
// FIXME: Should try to prevent any sort of issue at some point, free some memory that
// wasn't freed or destroy the ROT. Currently, it doesn't do much
void _error(GenericModem *pModem ) {
    // We destroy the ROT instance and return the status of the operation.
    _cleanup(pModem);
    return;
}

/******************************* External wrappers *******************************/
// The following funtions are external wrappers in C meant to facilitate the integration
// between the C++ library written by Thales and the Python library of the Middleware.
extern "C"
{
    PY_ERR GetRandom( uint8_t* pu8Data, uint16_t u16dataLen, const char* pModemPort, uint8_t u8LogLevel ) {
        PY_ERR Response = ERR_OK_PY;

        // We first check the inputs
        if( pu8Data == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if( u16dataLen == 0 ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if ( pModemPort == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        }

        if( Response != ERR_OK_PY ) {
            return ERR_INVALID_PARAMETERS_PY;
        }

        try {
            // We initialize the ROT
            Response = _init( pModemPort, u8LogLevel );

            // We run the actual function
            if( Response == ERR_OK_PY ) {
                int retVal = _py_ROT->generateRandom( pu8Data, u16dataLen );
                if( retVal != ERR_NOERR ) {
                    _log( PY_LOG_LEVEL_ERROR, "Error while getting entropy: %d", retVal );
                    throw retVal;
                }
                _log( PY_LOG_LEVEL_DEBUG, "Completed function call");
            }

            // The following is only useful if we are in debug mode (log level)
            if( Response == ERR_OK_PY ) {
                char buffer[256];
                for(int i = 0; i < u16dataLen; i++) {
                    snprintf(&buffer[2*i], sizeof(buffer), "%02X", pu8Data[i]);
                }
                _log( PY_LOG_LEVEL_DEBUG, "Random data: %s\n", buffer);
            }

            if( Response != ERR_OK_PY ) {
                throw Response;
            }

            // We destroy the ROT instance and return the status of the operation.
            _cleanup(&modem);
        } catch(...) {
            _log( PY_LOG_LEVEL_ERROR, "Error during the execution of: %s", __FUNCTION__ );
            _error(&modem);
            return ERR_GENERAL_PY;
        }
        return Response;
    }
}

// The following reads and returns a certificate based on a container ID.
extern "C"
{
    PY_ERR GetCertificate(
            uint32_t u32ContainerId,
            uint16_t u16BufferSize,
            uint8_t *pu8Cert,
            uint16_t *pu16CertLen,
            const char *pModemPort,
            uint8_t u8LogLevel ) {
        PY_ERR Response = ERR_OK_PY;

        // We first check the inputs
        if( u32ContainerId < MIN_CONTAINER_ID || u32ContainerId > MAX_CONTAINER_ID ) {
            _log( PY_LOG_LEVEL_ERROR,
                "The container ID must be between %d and %d",
                MIN_CONTAINER_ID,
                MAX_CONTAINER_ID );
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if( pu8Cert == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if( pu16CertLen == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if ( pModemPort == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        }

        if( Response != ERR_OK_PY ) {
            return ERR_INVALID_PARAMETERS_PY;
        }

        try{
            // We initialize the ROT
            Response = _init( pModemPort, u8LogLevel );

            // We run the function
            if( Response == ERR_OK_PY ) {
                // The function to retrieve a certificate takes a pointer to uint8_t
                // instead of a uint32_t, so we pass a pointer to the uint32 and
                // pass the length of the uint32. Note that we select only the first
                // byte of the containerID as they should range between 01 and 0A.
                int retVal = _py_ROT->getCertificateByContainerId(
                        (uint8_t*)&u32ContainerId,
                        sizeof(uint8_t),
                        u16BufferSize,
                        pu8Cert,
                        pu16CertLen );

                if( retVal != ERR_NOERR ) {
                    _log( PY_LOG_LEVEL_ERROR, "Error while retrieving certificate: %d", retVal );
                    throw retVal;
                }
            }

            // Although this is not ideal, it seems that the getCertificateByContainerId function
            // (which ultimately calls the "readFile" function) does not really return the length
            // of the certificate. According to documentation, the Applet should return 256 bytes
            // of the file or less if reaching the end of the file. However, it seems that this is
            // not the case and the Applet always return 256 bytes of data and a bunch of 0 if the
            // end of the file has been reached. Since this function deals with certificates, we'll
            // assume that we are dealing with ASN.1 encoded data, which means we can retrieve the
            // size of the certificate from the encoding. Again, this is not an ideal solution.
            if( Response == ERR_OK_PY ) {
                Response = GetAsn1LenFromOctetString( pu8Cert, pu16CertLen );
                _log( PY_LOG_LEVEL_DEBUG, "Retrieved certificate of length: %d", *pu16CertLen );
            }

            if( Response != ERR_OK_PY ) {
                throw Response;
            }

            _cleanup(&modem);
        } catch(...) {
            _log( PY_LOG_LEVEL_ERROR, "Error during the execution of: %s", __FUNCTION__ );
            _error(&modem);
            return ERR_GENERAL_PY;
        }
        return Response;
    }
}

// The following wrapper reads the URL and the port and return the JSON string
// containing both.
extern "C"
{
    PY_ERR GetURLAndPort(
            uint8_t *pu8UrlAndPortString,
            uint16_t *pu16UrlAndPortLen,
            const char *pModemPort,
            uint8_t u8LogLevel ) {
        PY_ERR Response = ERR_OK_PY;

        // We first check the inputs
        if( pu8UrlAndPortString == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if( pu16UrlAndPortLen == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if ( pModemPort == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        }

        if( Response != ERR_OK_PY ) {
            return ERR_INVALID_PARAMETERS_PY;
        }

        try{
            // We initialize the ROT
            Response = _init( pModemPort, u8LogLevel );

            // We run the function
            uint8_t u8aBuffer[MAX_SIZE_URL_PORT] = {0};
            if( Response == ERR_OK_PY ) {
                // Contrary to the "GetCertificate" function, there is a single
                // container ID used for the URL and Port.
                uint8_t u8ContainerId[CONTAINER_ID_LENGTH] = {CONTAINER_ID_PORT_AND_URL};
                int retVal = _py_ROT->getCertificateByContainerId(
                        u8ContainerId,
                        CONTAINER_ID_LENGTH,
                        MAX_SIZE_URL_PORT,
                        u8aBuffer,
                        pu16UrlAndPortLen );

                if( retVal != ERR_NOERR ) {
                    _log( PY_LOG_LEVEL_ERROR, "Error while retrieving certificate: %d", retVal );
                    throw retVal;
                }
            }

            // Although this is not ideal, we measure the length of the JSON string by checking how
            // many characters appear between the first and last accolades.
            if( Response == ERR_OK_PY ) {
                Response = GetJsonStringLen( u8aBuffer, MAX_SIZE_URL_PORT, pu16UrlAndPortLen );
                _log( PY_LOG_LEVEL_DEBUG, "Retrieved certificate of length: %d", *pu16UrlAndPortLen );
            }

            if( Response != ERR_OK_PY ) {
                throw Response;
            } else {
                // This last step is to only fill the buffer with the JSON string
                memcpy( pu8UrlAndPortString, u8aBuffer, *pu16UrlAndPortLen );
            }

            _cleanup(&modem);
        } catch(...) {
            _log( PY_LOG_LEVEL_ERROR, "Error during the execution of: %s", __FUNCTION__ );
            _error(&modem);
            return ERR_GENERAL_PY;
        }
        return Response;
    }
}

// The following performs a signature and returns it. Currently, the hash is hardcoded to
// be SHA256. Since this function is called from Python, it would perhaps be a good idea to
// perform the hash in Python (and thus have a more flexible implementation for the hash).
// Note that to establish the TLS connection, we need to call the GenerateRawSignature
// instead of this one. Therefore, this function shouldn't really be called, but it was
// kept in the code.
extern "C"
{
    PY_ERR GenerateSignature(
            char *pu8Message,
            uint16_t u16MessageLen,
            uint8_t *pu8Signature,
            uint16_t *pu16SignatureLen,
            const char *pModemPort,
            uint8_t u8LogLevel ) {
        PY_ERR Response = ERR_OK_PY;

        // We first check the inputs
        if( pu8Message == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if( pu8Signature == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if( u16MessageLen == 0 ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if ( pModemPort == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if ( pu16SignatureLen == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        }

        if( Response != ERR_OK_PY ) {
            return ERR_INVALID_PARAMETERS_PY;
        }

        try{
            // We initialize the ROT
            Response = _init( pModemPort, u8LogLevel );

            // Since the rest of the code is pretty much hardcoded for SHA256,
            // we will do the same (although this is not ideal). This is why
            // we generate the following vector of 0X20 = 32 bytes = 256 bits.
            std::vector<uint8_t> hash_val(MAX_HASH_LEN);

            // To be compatible with the current functions. We need to convert
            // the "C-type" string as a "C++-type" string. Note that the +1 is
            // for the string terminator.
            char buffer[u16MessageLen + 1];
            snprintf( buffer, sizeof(buffer), "%.*s", u16MessageLen + 1, pu8Message );
            _log( PY_LOG_LEVEL_DEBUG, "Signing message: \"%s\"", buffer );
            std::string strMessage = buffer;

            // We perform the hash of the message.
            if( Response == ERR_OK_PY ) {
                computeSha256( buffer, hash_val );
                _log( PY_LOG_LEVEL_DEBUG, "Performed hash of the message" );
            }

            // We perform the signature of the hash. Again, we fix the length
            // of the signature to 64 bytes, which isn't ideal...
            std::vector<uint8_t> sign_val(MAX_SIGNATURE_LEN);
            if( Response == ERR_OK_PY ) {
                int retVal = computeSignature( _py_ROT, hash_val, sign_val );
                if( retVal != ERR_NOERR ) {
                    _log( PY_LOG_LEVEL_ERROR, "Error while generating the signature: %d", retVal );
                    Response = ERR_GENERATING_SIG_PY;
                } else {
                    _log( PY_LOG_LEVEL_DEBUG, "Successfully computed signature" );
                    // Here we print the value of the signature. Note that the 'false' parameter
                    // will print "/" and "+" instead of "-" and "_". Furthermore, the 'true'
                    // parameter will pad the output with "=" signs if needed.
                    std::string encoded_signature = encodeBase64(reinterpret_cast<const char*>(sign_val.data()), sign_val.size(), false, true);
                    _log( PY_LOG_LEVEL_INFO, "Signature: %s", encoded_signature.c_str() );

                    // We comment this one out for now, but it should correspond to the
                    // hex string of the signature
                    // DumpMessage( (unsigned char*)sign_val.data(), (char *)"Signature (Bytes)", 0, sign_val.size());
                }
            }

            // We convert the signature back to "C-type" variables.
            // Currently, using "sign_val.size()" only provides the length of the buffer. We want to
            // return a more accurate value for the length of the signature. Note that the length of the
            // signature is at most 2 x 32 bytes (for SHA256) so 64 bytes (this may change slightly from
            // one signature to the next). Additionnally, there is ASN.1 encoding that add six bytes.
            if( Response == ERR_OK_PY ) {
                memcpy( pu8Signature, (uint8_t*)sign_val.data(), sign_val.size() );
                Response = GetAsn1LenFromOctetString( pu8Signature, pu16SignatureLen );
            }

            if( Response != ERR_OK_PY ) {
                _log( PY_LOG_LEVEL_ERROR, "Error during the generation of the signature: %d", Response );
                throw Response;
            }

            _cleanup(&modem);
        } catch(...) {
            _log( PY_LOG_LEVEL_ERROR, "Error during the execution of: %s", __FUNCTION__ );
            _error(&modem);
            return ERR_GENERAL_PY;
        }
        return Response;
    }
}

// The following performs a signature and returns it. This is a raw signature
// without a hash. This is the function that must be called (ultimately from
// Golang) to provide client authentication.
extern "C"
{
    PY_ERR GenerateRawSignature(
            char *pu8Message,
            uint16_t u16MessageLen,
            uint8_t *pu8Signature,
            uint16_t *pu16SignatureLen,
            const char *pModemPort,
            uint8_t u8LogLevel ) {
        PY_ERR Response = ERR_OK_PY;

        // We first check the inputs
        if( pu8Message == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if( pu8Signature == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if( u16MessageLen == 0 ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if ( pModemPort == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        } else if ( pu16SignatureLen == NULL ) {
            Response = ERR_INVALID_PARAMETERS_PY;
        }

        if( Response != ERR_OK_PY ) {
            return ERR_INVALID_PARAMETERS_PY;
        }

        try{
            // We initialize the ROT
            Response = _init( pModemPort, u8LogLevel );

            // For debugging only. Note that the -1 is to remove the string terminator necessary
            // for Python to send the message to C++
            // DumpMessage( (unsigned char*)pu8Message, (char*)"Message", 0, u16MessageLen - 1 );

            // We perform the signature of the hash.
            if( Response == ERR_OK_PY ) {
                int retVal = computeSignatureC(
                    _py_ROT,
                    (uint8_t*)pu8Message,
                    u16MessageLen - 1,  // See note above about "-1"
                    pu8Signature,
                    pu16SignatureLen );
                if( retVal != ERR_NOERR ) {
                    _log( PY_LOG_LEVEL_ERROR, "Error while generating the signature: %d", retVal );
                    Response = ERR_GENERATING_SIG_PY;
                } else {
                    _log( PY_LOG_LEVEL_DEBUG, "Successfully computed signature" );
                    // DumpMessage( (unsigned char*)pu8Signature, (char *)"Signature (Bytes)", 0, *pu16SignatureLen);
                }
            }

            // We convert the signature back to "C-type" variables.
            // Currently, using "sign_val.size()" only provides the length of the buffer. We want to
            // return a more accurate value for the length of the signature. Note that the length of the
            // signature is at most 2 x 32 bytes (for SHA256) so 64 bytes (this may change slightly from
            // one signature to the next). Additionnally, there is ASN.1 encoding that add six bytes.
            if( Response == ERR_OK_PY ) {
                Response = GetAsn1LenFromOctetString( pu8Signature, pu16SignatureLen );
            }

            if( Response != ERR_OK_PY ) {
                _log( PY_LOG_LEVEL_ERROR, "Error during the generation of the signature: %d", Response );
                throw Response;
            }

            _cleanup(&modem);
        } catch(...) {
            _log( PY_LOG_LEVEL_ERROR, "Error during the execution of: %s", __FUNCTION__ );
            _error(&modem);
            return ERR_GENERAL_PY;
        }
        return Response;
    }
}


/************************************ Static functions *************************************************/
/*
 * Retrieves the length from an ASN.1 encoded octet string.
 * This function simply ensures that the first byte is "30"
 * which should correspond to an ASN.1 octet string. Then,
 * we check the second parameter which should be the length
 * of the ASN.1 encoded value. We add 2 to this value to account
 * for the "30" and the length byte and we return this value. Note
 * that if the second parameter starts with "8", it means that the next
 * numbers will represent the length.
 *
 * @param[in] pu8Asn1Buffer: Pointer to asn.1 encoded buffer
 * @param[out] pu16Len:      Pointer to length which will be filled
 * @return PY_ERR:           Error status
 */
PY_ERR GetAsn1LenFromOctetString(
        uint8_t *pu8Asn1Buffer,
        uint16_t *pu16Len ){
    PY_ERR err = ERR_OK_PY;

    if( pu8Asn1Buffer == NULL ) {
        err = ERR_INVALID_PARAMETERS_PY;
    } else if( pu16Len == NULL ) {
        err = ERR_INVALID_PARAMETERS_PY;
    }

    // We ensure that the first byte indicates that we are dealing with an octet string
    if( err == ERR_OK_PY ){
        if (*pu8Asn1Buffer != ASN1_OCTET_STRING_ID) {
            _log( PY_LOG_LEVEL_ERROR, "The object given is not an ASN.1 encoded octet string");
            err = ERR_INVALID_PARAMETERS_PY;
        }
    }

    // We now read the second value which correspond to the length of the buffer.
    // Check the description of this function for the explanation regarding the "+2"
    uint16_t u16BufferLen = 0;
    if( err == ERR_OK_PY ) {
        uint8_t u8LengthByte = *(pu8Asn1Buffer + 1);
        if( (u8LengthByte & 0X80) == 0 ) {
            // If the first bit is 0, then we use the short form, i.e., only the first byte
            // should be the length
            u16BufferLen = (0xFF & u8LengthByte) + 2;
        } else {
            // If the first bit was not 0, then we use the long form, i.e., the
            // "u8LengthByte" variable will give the number of bytes that are
            // used to provide the length. For instance, 82 means that the next
            // 2 bytes will provide the length of the octet string.
            uint8_t u8NbrBytes = u8LengthByte & 0x7F;

            // Since we only provide a uint 16 pointer, we can only have two bytes here:
            if( u8NbrBytes > sizeof(u16BufferLen) ) {
                _log( PY_LOG_LEVEL_ERROR, "The octet string is too large for the buffer");
                err = ERR_NOT_ENOUGH_MEMORY_PY;
            }

            // Currently this is slightly pointless, but it will reduce the effort if
            // we ever want to switch to uint32 for the size.
            if( err == ERR_OK_PY ) {
                for( int i = 0; i < u8NbrBytes; i++ ) {
                    // The first part selects the ith element of the length. Note that the
                    // "+2" is to skip the tag byte as well as the length indicator (0x82).
                    // So let's use the string 0x30, 0x82, 0x02, 0x69 ... When i == 0, then
                    // we point to 0x02. The second part shifts the bits to the most significant
                    // position. So the 0x02 would be shifted by 1 group of 8 bits in this case.
                    u16BufferLen += (0xFF & *(pu8Asn1Buffer + 2 + i)) << ( 8 * (u8NbrBytes - i - 1) );
                }

                // Here, we need to add the last 4 bytes: 0x30, 0x82, 0x02 0x69 if we recall our
                // previous example
                u16BufferLen += 4;
            }
        }
    }

    if( err == ERR_OK_PY ) {
        _log( PY_LOG_LEVEL_DEBUG, "Size of buffer: %d", u16BufferLen);
        *pu16Len = u16BufferLen;
    }

    return err;
}

// We extract the JSON string. This is not by any means a perfect implementation.
// Python has a lot more tools for parsing JSON, so we just extract the bytes between
// the two accolades.
PY_ERR GetJsonStringLen(
        unsigned char* pJsonString,
        uint16_t u16MaxLen,
        uint16_t *pu16StringLen ){
    PY_ERR err = ERR_OK_PY;

    if( pJsonString == NULL ) {
        err = ERR_INVALID_PARAMETERS_PY;
    } else if( pu16StringLen == NULL ) {
        err = ERR_INVALID_PARAMETERS_PY;
    }

    // We start with an accolade as the first character to identify the JSON string
    if( err == ERR_OK_PY ) {
        if( pJsonString[0] != '{' ){
            _log( PY_LOG_LEVEL_ERROR, "The string provided was not a JSON string" );
            err = ERR_INVALID_PARAMETERS_PY;
        }
    }

    // We then continue reading the string. We keep track of the number of open accolades
    // encountered to know when we see the last one
    if( err == ERR_OK_PY ) {
        uint16_t u16NbrAccolades = 0;
        for( int i = 1; i < u16MaxLen; i++ ) {
            if( pJsonString[i] == '{' ) {
                u16NbrAccolades++;
            } else if( pJsonString[i] == '}' ) {
                if( u16NbrAccolades == 0 ) {
                    *pu16StringLen = i + 1;
                    break;
                } else {
                    u16NbrAccolades--;
                }
            }

            // If we reach this point, it means that we never found the last accolade
            if( i + 1 == u16MaxLen ) {
                _log( PY_LOG_LEVEL_ERROR, "The URL and port string is not properly formatted" );
                err = ERR_BAD_FORMAT_PY;
            }
        }
    }

    return err;
}

PY_ERR DumpMessage(
		unsigned char* pMsg,
		char* pBufferName,
		unsigned uOffset,
		unsigned uMsgLength ){

    PY_ERR err = ERR_OK_PY;

    if( !pMsg ){
        err = ERR_INVALID_PARAMETERS_PY;
    } else if( !pBufferName ){
        err = ERR_INVALID_PARAMETERS_PY;
    //We display 2 bytes words
    } else if( uMsgLength % 2 != 0 ){
        uMsgLength -= 1;
    }

    if( err == ERR_OK_PY ){
        // The +1 is to ensure we have a string terminator and the *5 is because we use
        // 9 characters per 2 bytes word of the pMsg, so we round it up to 5 characters
        // per byte
        char* pBuffer = (char*) malloc((uMsgLength * 5 + 1) * sizeof(char));
        int pos = 0;

        //Iteratively adding 16 bit words in the buffer
        for( int i = 1 + uOffset; i < uMsgLength + uOffset; i+=2 ){
            // For the last element, we don't print the '/'
            if( i + 2 >= uMsgLength ){
                pos += sprintf( pBuffer+pos, "%02x%02x", *(pMsg + i - 1), *(pMsg + i) );
            } else {
                pos += sprintf( pBuffer+pos, "%02x%02x", *(pMsg + i - 1), *(pMsg + i) );
            }
        }

        printf("Content of %s is: %s\n", pBufferName, pBuffer );
        free( pBuffer );
    }

    return err;
}

