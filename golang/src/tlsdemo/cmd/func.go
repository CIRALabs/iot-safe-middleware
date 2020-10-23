/*******************************************************************************
 * Title:       func.go
 * Author:      O. C.
 * Project:     IoT Safe Middleware
 * Description: The current file implements different functions related to
 *              the project
 * Functions:
 *  - ParseCertFromSingleLine
 *  - ParseResponse
 *  - MsgHandling
 *  - FormAddress
 *  - GetIoTPrivateKey
 *  - GetIotSafeMiddlewareLocation
 *  - runCommandGetOutput
 *  - runCommand
 *  - initConfig
 *  - initFlags
 *  - printUsage
*******************************************************************************/

package main

import(
    "os"
    "fmt"
    "flag"
    "errors"
    "strings"
    "os/exec"
    "crypto/x509"
    "encoding/pem"
    "path/filepath"
    "tlsdemo/common"
    "github.com/op/go-logging"
    mqtt "github.com/eclipse/paho.mqtt.golang"
)

/*******************************************************************************
 *  \brief Parses a certificate from a single line
 *
 * When a certificate is returned by Python, it is returned in a single line. We
 * Need to parse its content to be compatible with the "pem.Decode" method. We
 * return the pem block for the certificate
 *
 * @param  CertificateStr String containing the certificate on a single line
 * @return Pointer to PEM block
 * @return Error status
*******************************************************************************/
func ParseCertFromSingleLine( CertificateStr string ) (*pem.Block, error) {
    var pemStart     = "-----BEGIN "
    var pemEnd       = "-----END "
    var pemEndOfLine = "-----"

    // We find the first line
    BeginIdx := strings.Index( CertificateStr, pemStart )
    if BeginIdx != -1 {
        BeginIdx += len(pemStart)
        BeginIdx += strings.Index( CertificateStr[BeginIdx:], pemEndOfLine )
        BeginIdx += len(pemEndOfLine)
    } else {
        BeginIdx = 0
    }

    // We find the last line of the file
    EndIdx := strings.LastIndex( CertificateStr, pemEndOfLine )
    if EndIdx != -1 {
        EndIdx = strings.LastIndex( CertificateStr[:EndIdx], pemEnd )
    } else {
        EndIdx = len(CertificateStr) - 1
    }

    // We remove the first and last line
    CertificateContentStr := CertificateStr[BeginIdx:EndIdx]

    // We add new lines after each 64 characters
    buffer := ""
    for i := BeginIdx; i < EndIdx; i+=64 {
        if i + 64 < EndIdx {
            buffer = fmt.Sprintf("%s\n%s", buffer, CertificateStr[i:i+64])
        } else {
            buffer = fmt.Sprintf("%s\n%s\n", buffer, CertificateStr[i:EndIdx])
        }
    }

    // We now add the first and last line
    CertificateContentStr = fmt.Sprintf("%s%s%s",
                                CertificateStr[:BeginIdx],
                                buffer,
                                CertificateStr[EndIdx:])

    ClientCertPem, rest := pem.Decode( []byte( CertificateContentStr ) )
    if len(rest) != 0 {
        return nil, errors.New("Couldn't parse certificate")
    } else if ClientCertPem == nil {
        return nil, errors.New("Couldn't parse certificate")
    }
    return ClientCertPem, nil
}

/*******************************************************************************
 *  \brief Function used to parse the output of a command from iot-mw.py
 *
 * The format of the CmdOutput is:
 * <CmdOutput> = <KeyName>:<value>
 *
 * @param CmdOutput     The string output of the command to iot-mw.py
 * @param KeyName       The keyname used to retrieve the desired information
*******************************************************************************/
func ParseResponse( CmdOutput, KeyName string ) (string, error) {
    Lines := strings.Split( CmdOutput, "\n" )

    for i := 0; i < len(Lines); i++ {
        // If we're expecting a response, we should parse it with the separator ":"
        ParsedOutput := strings.Split( Lines[i], ":" )

        if len(ParsedOutput) != 2 {
            // Skipping
            continue
        } else if !strings.EqualFold( ParsedOutput[0], KeyName ) {
            // Skipping
            continue
        } else {
            return strings.TrimSpace( ParsedOutput[1] ), nil
        }
    }
    return "", errors.New("Error parsing the response")
}

/*******************************************************************************
 *  \brief Just printing received messages for testing
 *
 * This is a callback function to the "Subscribe()" function, don't modify the
 * input/output parameters.
 *
 * @param Client       MQTT cient
 * @param Message      MQTT message
*******************************************************************************/
func MsgHandling(Client mqtt.Client, Message mqtt.Message) {
    fmt.Printf( "Received message on topic '%s': %s\n", Message.Topic(), string(Message.Payload()) )
}

/*******************************************************************************
 *  \brief Forms the address to connect to
 *
 * Format of address is <protocol>://<url>:<port>. Note that there are no real
 * verifications in this command to see if the Url, port or protocol is properly
 * formatted or supported.
 *
 * @param Url       String indicating the URL
 * @param Port      String indicating the port
 * @param Protocol  String indicating the protocol
 *
 * @return The properly formatted protocol string
*******************************************************************************/
func FormAddress( Url, Port, Protocol string ) string {
    return fmt.Sprintf("%s://%s:%s", Protocol, Url, Port)
}

/*******************************************************************************
 *  \brief Creates a IoTPrivateKey
 *
 * Extracts a public key from a certificates and returns a pointer to a IoTPrivateKey.
 *
 * @param ClientCert     x509 certificate of the client
 *
 * @return Pointer to IoT private key
*******************************************************************************/
func GetIoTPrivateKey( ClientCert *x509.Certificate ) *IoTPrivateKey_t {
    return &IoTPrivateKey_t{PublicKey: ClientCert.PublicKey}
}

/*******************************************************************************
 *  \brief Retrieves the location of the script to access the Python functions
 *
 * In order to speed up development, it is also possible to set up an SSH
 * connection with a RaspberryPi and access its middleware from here. Check the
 * configuration.go file for more details
 *
 * @return The prefix for calling the iot_mw.py application
*******************************************************************************/
func GetIotSafeMiddlewareLocation( ) string {
    var Prefix string
    if IS_REMOTE {
        Prefix = fmt.Sprintf("ssh %s %s ", REMOTE_IP, IOT_MW_LOCATION)
    } else {
        Prefix = filepath.Join( os.Getenv( BUILD_DIR ), PY_RELATIVE_PATH )
    }

    if LOG_LEVEL == TRACE_LEVEL {
        Prefix = fmt.Sprintf("%s --debug ", Prefix)
    } else if LOG_LEVEL == DEBUG_LEVEL {
        Prefix = fmt.Sprintf("%s --notice", Prefix)
    }

    // We add the port just in case
    Prefix = fmt.Sprintf("%s --port %s ", Prefix, PY_MW_USB_PORT)
    return Prefix
}

/*******************************************************************************
 *  \brief Runs a command and captures the output
 *
 * @param CommandStr String constituting the command to be run
 * @return Error if any
 ******************************************************************************/
func runCommandGetOutput( CommandStr string ) ([]byte, error) {
    log.Debugf("Command: %s", CommandStr)
    // We form the command based on the input string
    ShellLocation, err := exec.LookPath( "sh" )
    if err != nil {
        return nil, err
    }

    Command := exec.Command( ShellLocation, "-c", CommandStr)
    Command.Stdin = os.Stdin
    Command.Stdout = nil
    Command.Stderr = os.Stderr

    // We run the command
    OutputBytes, err := Command.Output()
    if err != nil {
        return nil, err
    }
    if LOG_LEVEL <= DEBUG_LEVEL {
        fmt.Printf(string(OutputBytes))
    }
    return OutputBytes, nil
}

/*******************************************************************************
 *  \brief Runs a command
 *
 * @param CommandStr String constituting the command to be run
 * @param pConfig Pointer to configuration
 * @return Error if any
 ******************************************************************************/
func runCommand( CommandStr string, pConfig *Config_t ) (error) {

    // We first retrieve the "sh" from the system
    ShellLocation, err := exec.LookPath( "sh" )
    if err != nil {
        return err
    }

    Command := exec.Command( ShellLocation, "-c", CommandStr)
    Command.Stdin = os.Stdin
    Command.Stdout = os.Stdout
    Command.Stderr = os.Stderr

    return Command.Run()
}

/*******************************************************************************
 *  \brief Initializes configuration data structure
 *
 * @param pConfig Pointer to configuration
 * @return Error if any
 ******************************************************************************/
func initConfig( pConfig *Config_t ) error {
    // We setup the loggers. See earlier comment in function "ScriptLog" about
    // the two different loggers
    if pConfig.Flags.Verbosity.IsTrace {
        // From Golang's perspective, "trace" has the same behaviour as "debug".
        // However, we also modify the log level of the Python script
        LOG_LEVEL = TRACE_LEVEL
        logging.SetLevel( logging.DEBUG, "tlsdemo" )
    } else if pConfig.Flags.Verbosity.IsDebug {
        LOG_LEVEL = DEBUG_LEVEL
        logging.SetLevel( logging.DEBUG, "tlsdemo" )
    } else if pConfig.Flags.Verbosity.IsInfo {
        LOG_LEVEL = INFO_LEVEL
        logging.SetLevel( logging.INFO, "tlsdemo" )
    } else if pConfig.Flags.Verbosity.IsNotice {
        LOG_LEVEL = NOTICE_LEVEL
        logging.SetLevel( logging.NOTICE, "tlsdemo" )
    } else if pConfig.Flags.Verbosity.IsWarning {
        LOG_LEVEL = WARNING_LEVEL
        logging.SetLevel( logging.WARNING, "tlsdemo" )
    } else if pConfig.Flags.Verbosity.IsError {
        LOG_LEVEL = ERROR_LEVEL
        logging.SetLevel( logging.ERROR, "tlsdemo" )
    } else {
        // By default we will default to "INFO"
        LOG_LEVEL = INFO_LEVEL
        logging.SetLevel( logging.INFO, "tlsdemo" )
    }

    logging.SetFormatter( format )

    log.Debugf("Completed initialization of config")
    return nil
}

/*******************************************************************************
 *  \brief Initializes configuration
 *
 * @param pConfig Pointer to configuration
 * @return Error if any
 ******************************************************************************/
func initFlags( pConfig *Config_t ) error {
    // Verbose levels
    flag.BoolVar( &pConfig.Flags.Verbosity.IsTrace,   "trace",   false, "Verbosity: Trace level" )
    flag.BoolVar( &pConfig.Flags.Verbosity.IsDebug,   "debug",   false, "Verbosity: Debug level" )
    flag.BoolVar( &pConfig.Flags.Verbosity.IsInfo,    "info",    false, "Verbosity: Info level" )
    flag.BoolVar( &pConfig.Flags.Verbosity.IsNotice,  "notice",  false, "Verbosity: Notice level" )
    flag.BoolVar( &pConfig.Flags.Verbosity.IsWarning, "warning", false, "Verbosity: Warning level" )
    flag.BoolVar( &pConfig.Flags.Verbosity.IsError,   "error",   false, "Verbosity: Error level" )
    flag.StringVar( &pConfig.Port, "port", "/dev/ttyUSB0", "Serial port to connect to modem")

    flag.Parse()

    PY_MW_USB_PORT = pConfig.Port
    return nil
}

/*******************************************************************************
 *  \brief Displays usage of function
*******************************************************************************/
func printUsage( ) {
    fmt.Printf("Compilation version: %s\nDate of compilation: %s\n\n", COMPILATION_VERSION, COMPILATION_DATE)
    fmt.Println( "tlsdemo [-flags] <command> [parameters]" )
    fmt.Println( common.C4APrettyPrintBlock( "\nDescription: ", "This application is used as a demo to establish a 2-way authenticated TLS session. Note that to use this application, you must put the flags before the command. Note also that arguments in brackets \"[]\" are optional. For more information on a command's syntax, enter 'tlsdemo help <command>'", 80 ) )

    fmt.Println( "\nCommands:" )
    for i := 0; i < len( COMMAND_LIST ); i++ {
        fmt.Printf( "    %s\n",COMMAND_LIST[i].Name )
    }
    fmt.Println( "\nFlags:" )
    flag.Usage()
}
