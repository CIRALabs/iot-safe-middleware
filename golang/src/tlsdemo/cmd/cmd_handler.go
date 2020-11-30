/*******************************************************************************
 * Title:   cmd_handler.go
 * Author:  O. C.
 * Project: IoT Safe Middleware
 * Description: The current file implements the handler of the different commands.
 *              Each handler takes an array of strings and a pointer to the
 *              configuration. The array of strings represent the parameters
 *              entered by the user. Each command may have different subverbs,
 *              different mandatory parameters and different optional parameters.
 *              The appropriate commands will be called upon processing the
 *              different parameters.
 *
 * Functions:
 *  - hdlDemo
 *  - hdlHelp
*******************************************************************************/

package main

import(
    "fmt"
    "time"
    "tlsdemo/common"
    mqtt "github.com/eclipse/paho.mqtt.golang"
)

/*******************************************************************************
 *  \brief Runs the command demo
 *
 * @param Parameters  Array of parameters
 * @param pConfig     Pointer to configuration
 * @return Error status
*******************************************************************************/
func hdlDemo( Parameters []string, pConfig *Config_t ) error {
    // We define the parameters for this command. (Currently, it takes none)
    var err error
    Params := make( []*common.Param_t, 0 )

    // Parsing the parameters
    err = common.ProcessParameters( Parameters, Params )
    if err != nil {
        return err
    }

    // We interact with the middleware to extract the material necessary for a
    // TLS configuration.
    pTlsConfig, ConnectionStr, err := PrepareTlsConfig()
    if err != nil {
        return err
    }
    log.Infof("Attempting connection at %s", ConnectionStr)

    // We start preparing the MQTT configuration
    opts := mqtt.NewClientOptions()
    opts.AddBroker( ConnectionStr )
    opts.SetClientID("IoT-Device")
    opts.SetTLSConfig( pTlsConfig )
    opts.SetProtocolVersion( uint(4) ) // MQTT 3.1.1

    // Attempting to connect to the server for a number of times before asserting
    // that the connection failed
    mqttClient := mqtt.NewClient(opts)
    for i := 0; i < MAX_CONNECT_TRIES; i++ {
        if token := mqttClient.Connect();
            token.Wait() && token.Error() == nil {
            // Connection established
            log.Noticef("Connection established!")
            break
        } else if i == MAX_CONNECT_TRIES - 1 {
            return fmt.Errorf("Coulnd't establish connection")
        } else {
            log.Warningf("Error establishing the connection: %s", token.Error())
            time.Sleep(1 * time.Second)
        }
    }

    // We publish to a test topic
    if token := mqttClient.Publish( MQTT_TOPIC, 0, false, []byte("Hello from the IoT!") );
        token.Wait() && token.Error() != nil {
        return err
    } else {
        log.Noticef("Published to '%s'", MQTT_TOPIC)
    }

    // We subscribe to a test topic
    if token := mqttClient.Subscribe( MQTT_TOPIC, 0, MsgHandling );
        token.Wait() && token.Error() != nil {
        return err
    } else {
        log.Noticef("Subscribed to '%s'", MQTT_TOPIC)
    }

    // Waiting until Ctrl+C to publish messages. This technique reduces CPU usage
    // compared to an empty for loop
    select{ }

    return nil
}

/*******************************************************************************
 *  \brief Runs the command help
 *
 * @param Parameters  Array of parameters
 * @param pConfig     Pointer to configuration
 * @return Error status
*******************************************************************************/
func hdlHelp( Parameters []string, pConfig *Config_t ) error {
    // We define the parameters for this command
    var err error
    Params   := make( []*common.Param_t, 1 )
    Params[0] = &common.Param_t{ Position: 0,
                                     Type:     common.PARAM_TYPE_STRING,
                                     Syntax:   common.PARAM_SYNTAX_POSITIONAL,
                                     Default:  "" }

    // Parsing the parameters
    err = common.ProcessParameters( Parameters, Params )
    if err != nil {
        return err
    }

    CommandName := Params[0].Value.(string)

    // If there are no parameters passed to help, we simply print the usage
    if CommandName == "" {
        printUsage()
        return nil
    }

    // We get the description and the syntax of the command from the name. We
    // also ensure that the name of the command was valid
    Description := ""
    Syntax      := make( []string, 0 )
    for i := 0; i < len(COMMAND_LIST); i++ {
        if COMMAND_LIST[i].Name == CommandName {
            Description = COMMAND_LIST[i].Description
            for j := 0; j < len(COMMAND_LIST[i].Help); j++ {
                Syntax = append( Syntax, COMMAND_LIST[i].Help[j] )
            }
        }
    }

    if Description == "" || len(Syntax) == 0 {
        log.Fatalf("Invalid command '%s'.", CommandName)
    }

    // We print our buffer for the description
    fmt.Printf( common.C4APrettyPrintBlock("\nDescription: ", Description, 80) )
    fmt.Printf("\n\n")

    // We now print the help (i.e., the specific syntax for each subcommand)
    fmt.Printf("Syntax:       %s\n", Syntax[0])
    for i := 1; i < len(Syntax); i++ {
        fmt.Printf("              %s\n", Syntax[i])
    }

    fmt.Printf("\n")
    return nil
}
