/*******************************************************************************
 * Title:   configuration.go
 * Author:  O. C.
 * Project: IoT Safe Middleware
 * Description: The current file contains constants and variables that are used
 *              throughout the projet.
 *
 * Categories
 *  - Output of Python Commands
 *  - Connection Parameter
 *  - Remote Connection
 *  - Logging
*******************************************************************************/

package main

import (
    "github.com/op/go-logging"
)

// We need to create a new object that will pass as a crypto.Privatekey. The only
// important part is that we implement the functions "Sign()" and "Public()" using
// the exact same interface as a crypto.Privatekey. In addition, to gain some
// efficiency, we preload the public key inside this structure.
type IoTPrivateKey_t struct {
    PublicKey   interface{}
}


/*********************** Output of Python Commands ****************************/


var PY_MW_USB_PORT string
const BUILD_DIR            = "BUILD_DIR" // Environment variable set by setenv.sh to reach Python functions
const PY_RELATIVE_PATH     = "python/iot_mw.py"
const PY_PUBKEY_LABEL      = "PublicKey"
const PY_URL_LABEL         = "FQDN"
const PY_PORT_LABEL        = "Port"
const PY_SIGNATURE_LABEL   = "Signature"
const PY_CLIENT_CERT_LABEL = "ClientCert"
const PY_ASP_CERT_LABEL    = "AspCert"
const PY_PROVISION_LABEL   = "IsProvisioned"


/************************* Connection Parameters ******************************/
const MAX_CONNECT_TRIES    = 10
const CONN_PROTOCOL        = "ssl"
const MQTT_TOPIC           = "try-me"

/************************** Remote Connection *********************************/
// It is possible to run all the Python calls through an SSH connection.
const IS_REMOTE       = false
const REMOTE_IP       = "pi@192.168.7.42"
const IOT_MW_LOCATION = "/home/pi/Crypto4a/cira/middleware/python/iot_mw.py"


/******************************* Logging **************************************/


// Logger and format of the logger. This was taken directly from the example in
// https://github.com/op/go-logging
var log = logging.MustGetLogger("tlsdemo")
var format = logging.MustStringFormatter(
    `%{color}%{time:15:04} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

// We setup the log levels (Note that this is the equivalent of an enum)
const (
    TRACE_LEVEL = iota
    DEBUG_LEVEL
    INFO_LEVEL
    NOTICE_LEVEL
    WARNING_LEVEL
    ERROR_LEVEL
)

// When initializing the configuration, the log level gets set
var LOG_LEVEL int
