/*******************************************************************************
 * Title:   main.go
 * Author:  O. C.
 * Project: IoT Safe Middleware
 * Description: The purpose of the current project is to show how to establish a
 *              TLS session between an IoT device and a server by leveraging
 *              the IoT safe middleware application in Python.
*******************************************************************************/

package main

import(
    "os"
    "fmt"
    "flag"
    "errors"
)

// This structure is used to get the verbosity from the command line
type Verbosity_t struct {
    IsTrace   bool
    IsDebug   bool
    IsInfo    bool
    IsNotice  bool
    IsWarning bool
    IsError   bool
}

// This structure contains the different flags used in this tool
type Flags_t struct {
    Verbosity   Verbosity_t       ///< Verbosity level
}

// This structure contains the different parameters used in this program
type Config_t struct {
    Flags Flags_t      ///< Structure containing flags that can change the behaviour
}

// The existing commands can be used as a reference for writing additional commands.
type Command_t struct {
    Name        string
    Description string
    Help        []string
}

var DEMO_CMD = Command_t{
    Name: "demo",
    Description: "Runs a demo to show how a TLS session can be established between the IoT device and a server",
    Help: []string{ "tlsdemo [-flags] demo" } }

var HELP_CMD = Command_t{
    Name: "help",
    Description: "When used alone, displays general usage of the tool. When followed by a function's name, it displays more detailed explanation",
    Help: []string{ "tlsdemo [-flags] help [cmd <cmdName>]" } }

var VERSION_CMD = Command_t{
    Name: "version",
    Description: "Obtain version and date of compilation",
    Help: []string{ "tlsdemo [-flags] version" } }

// Command list
var COMMAND_LIST = []Command_t{ DEMO_CMD,
                                VERSION_CMD,
                                HELP_CMD }

// We add the compilation date to the script. Note that these are set by the script
// build.sh. To pass the values in the build process, proceed as follows:
// $ cd path/to/tlsdemo/cmd
// $ go build -ldflags "-X main.COMPILATION_DATE=`date -u +%D-%T` -X main.COMPILATION_VERSION=`echo <version>`"
var COMPILATION_DATE    string
var COMPILATION_VERSION string

func main() {

    // We initialize the configuration
    var err error
    var Config Config_t
    err = initFlags( &Config )
    if err == nil {
        err = initConfig( &Config )
    }

    if flag.NArg() >= 1 && err == nil {
        Parameters := make( []string, flag.NArg() - 1 )

        // We parse the parameters to the command
        for i := 1; i < flag.NArg(); i++ {
            Parameters[i - 1] = flag.Arg(i)
        }

        // We ensure that the command is valid
        ValidCommand := false
        for i := 0; i < len(COMMAND_LIST); i++ {
            if flag.Arg(0) == COMMAND_LIST[i].Name {
                ValidCommand = true
                break
            }
        }

        if !ValidCommand {
            printUsage()
            log.Fatalf( "Unknown command %s. Please try again.", flag.Arg(0) )
        }

        switch flag.Arg(0) {
            case DEMO_CMD.Name:
                err = hdlDemo( Parameters, &Config )
            case HELP_CMD.Name:
                err = hdlHelp( Parameters, &Config )
            case VERSION_CMD.Name:
                fmt.Printf("Compilation version: %s\nDate of compilation: %s\n\n", COMPILATION_VERSION, COMPILATION_DATE)
            default:
                err = errors.New( fmt.Sprintf("Invalid command '%s'", flag.Arg(0)) )
        }

    } else if err == nil {
       printUsage()
    }

    if err != nil {
        log.Error(err)
        os.Exit(1)
    }
}
