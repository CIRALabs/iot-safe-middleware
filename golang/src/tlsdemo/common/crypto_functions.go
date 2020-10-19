/*******************************************************************************
 * Title:   crypto_functions.go
 * Author: O. C.
 * Project: Common functions (common)
 * Description: The current file implements different functions related to
 *              various cryptographic operations
 * Functions:
 *  - ParsePubKey
 *  - ParsePrivKey
 *  - HashMsg
 *  - GenerateSignature
*******************************************************************************/

package common

import(
    "fmt"
    "hash"
    "errors"
    "crypto"
    "math/big"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "crypto/sha1"
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/elliptic"
)

// We define a type for the marshalling standards.
type MarshalStd_t struct {
    Name string
}

// We provide some predefined marshalling standards.
var PKCS1 = MarshalStd_t{ Name: "PKCS1" }
var PKCS8 = MarshalStd_t{ Name: "PKCS8" }
var PKIX  = MarshalStd_t{ Name: "PKIX" }

var MARSHAL_STD_LIST = []MarshalStd_t{
    PKCS1,
    PKCS8,
    PKIX,
}

// Defining the structure for a hash. The ID is the uint32 value that is used in
// the HSM to identify it.
type HashAlg_t struct {
    ID   uint32
    Name string
    Len  int
    Hash hash.Hash
}

// We define a type for the asymmetric key. This type is re-used for both signature
// and encryption
type AsymCipher_t struct {
    Name        string
    Type        string
    Len         int
    Curve       elliptic.Curve
    HashAlg     HashAlg_t        // This is used for signature and for OAEP
    PubMarsh    MarshalStd_t
    PrivMarsh   MarshalStd_t
}

// We marshal the ECDSA signature. We need to add a type as it is not exported
// in the crypto/ecdsa package
type ECDSASig_t struct {
    R, S *big.Int
}

// We provide some predefined hash
var SHA1   = HashAlg_t{ ID: 0x0000, Name: "SHA1",   Len: 32, Hash: sha1.New() }
var SHA256 = HashAlg_t{ ID: 0x0642, Name: "SHA256", Len: 32, Hash: sha256.New() }
var SHA384 = HashAlg_t{ ID: 0x0643, Name: "SHA384", Len: 48, Hash: sha512.New384() }
var SHA512 = HashAlg_t{ ID: 0x0644, Name: "SHA512", Len: 64, Hash: sha512.New() }

var HASH_ALG_LIST = []HashAlg_t{
    SHA256,
    SHA384,
    SHA512,
}

// We provide some predefined asymmetric algorithms. Note that the hash is for
// signatures
var RSA4096_SHA256 = AsymCipher_t{
    Name: "RSA4k_SHA256",
    Type: "RSA",
    Len: 4096,
    HashAlg: SHA256,
    PubMarsh: PKIX,
    PrivMarsh: PKCS8 }
var RSA2048_SHA256  = AsymCipher_t{
    Name: "RSA2k_SHA256",
    Type: "RSA",
    Len: 2048,
    HashAlg: SHA256,
    PubMarsh: PKIX,
    PrivMarsh: PKCS8 }
var RSA1024_SHA256  = AsymCipher_t{
    Name: "RSA1k_SHA256",
    Type: "RSA",
    Len: 1024,
    HashAlg: SHA256,
    PubMarsh: PKIX,
    PrivMarsh: PKCS8 }
var ECDSA256 = AsymCipher_t{
    Name: "ECDSA256",
    Type: "ECDSA",
    Len: 256,
    HashAlg: SHA256,
    Curve: elliptic.P256(),
    PubMarsh: PKIX,
    PrivMarsh: PKCS8 }
var ECDSA384 = AsymCipher_t{
    Name: "ECDSA384",
    Type: "ECDSA",
    Len: 384,
    HashAlg: SHA384,
    Curve: elliptic.P384(),
    PubMarsh: PKIX,
    PrivMarsh: PKCS8 }

var ASYM_ALG_LIST = []AsymCipher_t{
    RSA4096_SHA256,
    RSA2048_SHA256,
    ECDSA256,
    ECDSA384,
}

// No need to import another package (package "unsafe") to get the size of a
// uint32.
const SIZEOFUINT32 = 4


/*******************************************************************************
*  \brief Parses the public key
*
* Reforms the public key based on the marshalling standard that was used
* initially
*
* @param PubKeyBytes Array of bytes containing the public key
* @param MarshalStd Marshalling standard used
* @return Pointer to public key (nil if error)
*******************************************************************************/
func ParsePubKey( PubKeyBytes []byte, MarshalStd MarshalStd_t ) interface{} {
    var err error
    var PubKey interface{}

    // We try parsing the key directly
    if MarshalStd == PKCS1 {
        // PKCS1 is only valid for RSA key
        PubKey, err = x509.ParsePKCS1PublicKey( PubKeyBytes )
    } else if MarshalStd == PKIX {
        PubKey, err = x509.ParsePKIXPublicKey( PubKeyBytes )
    } else {
        return nil
    }

    if err == nil {
        return PubKey
    }

    // We will try to parse the public key as if it was from a certificate
    var pCert *x509.Certificate
    if err != nil {
        pCert, err = x509.ParseCertificate( PubKeyBytes )
        if err == nil {
            return pCert.PublicKey
        }
    }

    // If there was an error again, we try to prase the public key as if it was
    // from a certificate request
    if err != nil {
        pCsr, err := x509.ParseCertificateRequest( PubKeyBytes )
        if err == nil {
            return pCsr.PublicKey
        }
    }

    // If everything has failed at this point, we return nil
    return nil
}

/*******************************************************************************
*  \brief Parses the private key
*
* Reforms the private key based on the marshalling standard that was used
* initially
*
* @param PrivKeyBytes Array of bytes containing the private key
* @param MarshalStd   Marshalling standard used
* @return Pointer to private key (nil if error)
*******************************************************************************/
func ParsePrivKey( PrivKeyBytes []byte, MarshalStd MarshalStd_t ) interface{} {
    if MarshalStd == PKCS1 {
        // PKCS1 is only valid for RSA key
        PrivKey, err := x509.ParsePKCS1PrivateKey( PrivKeyBytes )
        if err != nil {
            // fmt.Printf("Error while parsing private key PKCS1: %s", err.Error())
            return nil
        }
        return PrivKey
    } else if MarshalStd == PKCS8 {
        PrivKey, err := x509.ParsePKCS8PrivateKey( PrivKeyBytes )
        if err != nil {
            // fmt.Printf("Error while parsing private key PKCS8: %s", err.Error())
            return nil
        }
        return PrivKey
    } else {
        return nil
    }
}

/*******************************************************************************
 *  \brief Hashing a message. Not callable from another package
 *
 * @param Content    Array of bytes containing the message to sign
 * @param HashAlg    Pointer to hash algorith,
 * @return Array of bytes containing the signature
*******************************************************************************/
func HashMsg( Content []byte, HashAlg *HashAlg_t ) []byte {
    Hash := HashAlg.Hash
    Hash.Reset()
    Hash.Write( Content )
    return Hash.Sum( nil )
}

/*******************************************************************************
 *  \brief Generates a signature of the message
 *
 * We find the digest of the message and then we sign it using our private key.
 *
 * @param Content    Array of bytes containing the message to sign
 * @param PrivateKey Pointer to private key structure
 * @param AsymAlg    Asymmetric used for validating the signature
 * @return Array of bytes containing the signature
 * @return error if any during the signature
*******************************************************************************/
func GenerateSignature( Content []byte, PrivateKey interface{}, AsymAlg AsymCipher_t ) ([]byte, error) {
    switch AsymAlg {
        case RSA1024_SHA256, RSA2048_SHA256, RSA4096_SHA256:
            // We convert the private key interface into the proper type
            PrivKey, _ := PrivateKey.(*rsa.PrivateKey)

            // We return the signature of the message
            return rsa.SignPKCS1v15( rand.Reader, PrivKey, crypto.SHA256, Content )//HashMsg(Content, &AsymAlg.HashAlg) )
        case ECDSA256, ECDSA384:
            // We convert the private key interface into the proper type
            PrivKey, ok := PrivateKey.(*ecdsa.PrivateKey)
            if !ok {
                return nil, errors.New( fmt.Sprintf("Got type %T but want *ecdsa.PrivateKey\n", PrivateKey) )
            }

            // We return the signature of the message
            return PrivKey.Sign( rand.Reader, HashMsg(Content, &AsymAlg.HashAlg), nil )
        default:
            return nil, errors.New("Signature algorithm not supported: " + AsymAlg.Name)
    }
}