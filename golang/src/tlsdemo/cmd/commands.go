/*******************************************************************************
 * Title:   commands.go
 * Author:  O. C.
 * Project: IoT Safe Middleware
 * Description: The current file implements the different commands that can be
 *              performed. There is not necessarily a 1-to-1 match with the functions
 *              in "cmd_handler.go" because some of the command handlers translate
 *              in multiple commands here. Note also that most of the following
 *              commands reproduce the functionalities of the original bash scripts
 *
 * Functions:
 * - PrepareTlsConfig
 * - MW_IsProvisioned
 * - MW_GetAllInfo
 * - (priv *IoTPrivateKey_t) Public
 * - (priv *IoTPrivateKey_t) Sign
 *******************************************************************************/

package main

import (
    "io"
    "fmt"
    "crypto"
    "crypto/tls"
    "crypto/x509"
    "tlsdemo/common"
    "encoding/base64"
)

/*******************************************************************************
 *  \brief Prepares the configuration for establishing a TLS session
 *
 * Retrieves all the information from the SIM card by calling the Python handler.
 * The Python handler already performs all the necessary validation of the
 * material by verifying the signatures and the certificates contained in the
 * SIM card. Then, this function parses the information for "Golang-compatibility"
 * and return a TLS config. This TLS config can then be used by the tls.Dial
 * function to establish a two-way authenticated TLS session.
 *
 * @return Pointer to TLS configuration
 * @return String of the URL and port to be used for the TLS session
 * @return Error status
*******************************************************************************/
func PrepareTlsConfig( ) (*tls.Config, string, error) {

    log.Debugf("Preparing TLS configuration")

    // We retrieve some information from the SIM card. Note that this information
    // was already validated in the middleware.
    ReturnInfo, err := MW_GetAllInfo()
    if err != nil {
        return nil, "", err
    }

    // We form the connection URL and port -> Protocol://<URL>:<Port>
    ConnectionStr := FormAddress( ReturnInfo[PY_URL_LABEL], ReturnInfo[PY_PORT_LABEL], CONN_PROTOCOL )

    // We parse both the client and the ASP certificates into bytes
    ClientCertPem, err := ParseCertFromSingleLine( ReturnInfo[PY_CLIENT_CERT_LABEL] )
    if err != nil {
        return nil, "", err
    }
    AspCertPem, err := ParseCertFromSingleLine( ReturnInfo[PY_ASP_CERT_LABEL] )
    if err != nil {
        return nil, "", err
    }

    // We form a certificate pool containing only the ASP certificate. This will configure
    // the root certificate which will be used by the client to authenticate the server.
    RootCertPool := x509.NewCertPool()
    AspCertx509, err := x509.ParseCertificate( AspCertPem.Bytes )
    if err != nil {
        return nil, "", err
    }
    RootCertPool.AddCert( AspCertx509 )

    // We parse the client certificate as well
    ClientCert, err := x509.ParseCertificate( ClientCertPem.Bytes )
    if err != nil {
        return nil, "", err
    }

    // We now prepare the TLS configuration. Here are a few notes:
    // 1 - The root CA will be used to validate the identity of the server.
    // 2 - Currently, the server doesn't support TLS1.3, so we pass TLS1.2 as the
    //     minimum version for maximal security.
    // 3 - We want to force the server to use RSA with AES 256-GCM and SHA384 as
    //     this is by far the most secure cipher suite that is supported both by
    //     Golang and by the server
    // 4 - The "GetClientCertificate" callback is essential for client authentication.
    //     If "Certificate" is not set, then the callback is simply ignored. Also,
    //     since the SIM card doesn't handle anything other than ECDSA SHA256,
    //     we must keep this value. Lastly, the private key is an object IoTPrivateKey_t
    //     that contains two methods (Public and Sign) that will pass as a
    //     crypto.PrivateKey
    // 5 - The "SupportedSignatureAlgorithms" is only supported from Golang 1.14, but
    //     it is required to perform appropriate authentication.
    // 6 - Although these parameters can be edited, it is recommended to double check
    //     carefully as they could compromise security/not perform client authentication
    TlsConfig := tls.Config{
        RootCAs: RootCertPool,
        MinVersion: tls.VersionTLS12,
        PreferServerCipherSuites: false,
        CipherSuites: []uint16{
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA },
        GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
            return &tls.Certificate{
                Certificate: [][]byte{ ClientCertPem.Bytes },
                Leaf: ClientCert,
                SupportedSignatureAlgorithms: []tls.SignatureScheme{ tls.ECDSAWithP256AndSHA256 },
                PrivateKey:  GetIoTPrivateKey( ClientCert ),
            }, nil
        },
    }

    return &TlsConfig, ConnectionStr, nil
}

/*******************************************************************************
 *  \brief Check if SIM card is provisioned
 *
 * @return True if card is provisioned
 * @return Error status
*******************************************************************************/
func MW_IsProvisioned( ) (bool, error) {
    CommandStr := fmt.Sprintf("%s isProvisioned", GetIotSafeMiddlewareLocation())
    OutputBytes, err := runCommandGetOutput( CommandStr )
    if err != nil {
        return false, fmt.Errorf("Error while checking if SIM card is provisioned: %s", err.Error())
    }

    IsProvisioned, err := ParseResponse( string(OutputBytes), PY_PROVISION_LABEL )
    if err != nil {
        return false, err
    } else if IsProvisioned != "true" {
        return false, fmt.Errorf("The SIM card was not provisioned")
    }

    return true, nil
}

/*******************************************************************************
 *  \brief Extract information from the SIM card
 *
 * Retrieves the URL and the Port from the SIM card and checks all the certificates
 * and signatures.
 *
 * @return Map containing the following information
 *      PY_ASP_CERT_LABEL:     ASP certificate
 *      PY_CLIENT_CERT_LABEL:  Client certificate
 *      PY_URL_LABEL:          URL of the server endpoint
 *      PY_PORT_LABEL:         Port of the server endpoint
 * @return Error status
*******************************************************************************/
func MW_GetAllInfo() (map[string]string, error){

    log.Infof("Retrieving information from SIM card")

    // We first check to see if the SIM card was provisioned
    IsProvisioned, err := MW_IsProvisioned( )
    if err != nil {
        return nil, fmt.Errorf("Error while checking if SIM card is provisioned: %s", err.Error())
    } else if !IsProvisioned {
        return nil, fmt.Errorf("SIM card was not provisioned")
    }

    // We extract the public key by calling the Python middleware
    CommandOutput, err := runCommandGetOutput( fmt.Sprintf("%s getAllInfo", GetIotSafeMiddlewareLocation()) )
    if err != nil {
        return nil, fmt.Errorf("Couldn't retrieve the information from the SIM card: %s", err.Error())
    }

    // URL
    URL, err := ParseResponse( string(CommandOutput), PY_URL_LABEL )
    if err != nil {
        return nil, fmt.Errorf("Couldn't parse the URL: %s", err.Error())
    }

    // Port
    Port, err := ParseResponse( string(CommandOutput), PY_PORT_LABEL )
    if err != nil {
        return nil, fmt.Errorf("Couldn't parse the port: %s", err.Error())
    }

    // Client Certificate
    ClientCertificate, err := ParseResponse( string(CommandOutput), PY_CLIENT_CERT_LABEL )
    if err != nil {
        return nil, fmt.Errorf("Couldn't parse response to retrieve the client certificate: %s", err.Error())
    }

    // ASP Certificate
    AspCertificate, err := ParseResponse( string(CommandOutput), PY_ASP_CERT_LABEL )
    if err != nil {
        return nil, fmt.Errorf("Couldn't parse response to retrieve the ASP certificate: %s", err.Error())
    }

    // Output map
    OutputMap := make( map[string]string )
    OutputMap[PY_URL_LABEL]         = URL
    OutputMap[PY_PORT_LABEL]        = Port
    OutputMap[PY_ASP_CERT_LABEL]    = AspCertificate
    OutputMap[PY_CLIENT_CERT_LABEL] = ClientCertificate
    return OutputMap, nil
}

/*******************************************************************************
 *  \brief Returns the client public key
 *
 * DO NOT MODIFY INTERFACE
 *
 * @return Interface of the public key
*******************************************************************************/
func (priv *IoTPrivateKey_t) Public() crypto.PublicKey{
    // If the public key is already defined in the structure, we return it. This
    // is preferable as it is more efficient
    if priv.PublicKey != nil {
        return priv.PublicKey
    }

    // We extract the public key by calling the Python middleware
    CommandOutput, err := runCommandGetOutput( fmt.Sprintf("%s getPublicKey", GetIotSafeMiddlewareLocation()) )
    if err != nil {
        log.Fatalf("Couldn't retrieve the public key from the SIM card: %s", err.Error())
    }

    // We decode the response from the command
    PublicKeyStr, err := ParseResponse( string(CommandOutput), PY_PUBKEY_LABEL )
    if err != nil {
        log.Fatalf("Couldn't parse response to retrieve public key: %s", err.Error())
    }
    PublicKeyPem, err := ParseCertFromSingleLine( PublicKeyStr )
    if err != nil {
        log.Fatalf("Couldn't parse certificate: %s", err.Error())
    }

    // We parse the public key
    PublicKey := common.ParsePubKey( PublicKeyPem.Bytes, common.PKIX )
    if PublicKey == nil {
        log.Fatalf("Couldn't parse the public key using PKIX")
    }

    return PublicKey
}

/*******************************************************************************
 *  \brief Extracts the client public key from the SIM card
 *
 * We perform a signature on a digest. Note that the other inputs are ignored as
 * the signature is performed directly on the SIM card. The reason why they are
 * provided is only so "IoTPrivateKey_t" passes as a crypto.Privatekey
 *
 * DO NOT MODIFY INTERFACE
 *
 * @param rand       Ignored
 * @param digest     Array of bytes result of a hash to be signed
 * @param opts       Ignored
 * @return signature Array of bytes of the signature
 * @return err       Error if any
*******************************************************************************/
func (priv *IoTPrivateKey_t) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
    // We start by encoding the digest as a string of base64 characters
    ToBeSigned := base64.StdEncoding.EncodeToString( digest )

    // We extract the public key by calling the Python middleware. Notice that we
    // need to perform raw signatures to be compatible with Golang's implementation.
    // The hashing will be performed prior to calling this function.
    CommandOutput, err := runCommandGetOutput( fmt.Sprintf("%s sign --raw --tbs %s", GetIotSafeMiddlewareLocation(), ToBeSigned) )
    if err != nil {
        return nil, fmt.Errorf("Couldn't perform a signature: %s", err.Error())
    }

    // We decode the response from the command
    SignatureStr, err := ParseResponse( string(CommandOutput), PY_SIGNATURE_LABEL )
    if err != nil {
        return nil, fmt.Errorf("Couldn't parse the FQDN: %s", err.Error())
    }

    // The signature is returned as a base64 encoded string
    Signature, err := base64.StdEncoding.DecodeString( SignatureStr )
    if err != nil {
        return nil, err
    }

    return Signature, err
}
