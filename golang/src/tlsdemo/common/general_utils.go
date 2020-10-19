/*******************************************************************************
 * Title:   general_utils.go
 * Author: O. C.
 * Project: Common functions (common)
 * Description: The current file implements different functionalities that can
 *              be used over various projects and are quite general purpose.
 * Functions:
 *  - ProcessParameters
 *  - processOneParameter
 *  - C4APrettyPrintBlock: Prints a block of information with indenting and max
 *                         width
*******************************************************************************/

package common

import (
    "fmt"
    "errors"
    "strings"
    "strconv"
    "encoding/hex"
)

const PARAM_SYNTAX_STANDALONE = 0
const PARAM_SYNTAX_WITH_VAL   = 1
const PARAM_SYNTAX_SUBVERB    = 2
const PARAM_SYNTAX_POSITIONAL = 3

const PARAM_TYPE_STRING       = 0
const PARAM_TYPE_INT          = 1
const PARAM_TYPE_BOOL         = 2
const PARAM_TYPE_PUB_MARSHAL  = 3
const PARAM_TYPE_PRIV_MARSHAL = 4
const PARAM_TYPE_HASH_ALG     = 5
const PARAM_TYPE_HEX_BYTES    = 6

// Structure holding all the information relevant for a parameter
type Param_t struct {
    Name      string
    Type      int
    Syntax    int
    Processed bool
    Position  int
    Value     interface{}
    Default   interface{}
}

/*******************************************************************************
 *  \brief Processes a list of parameters
 *
 * @param InputParams  Array of strings containing the parameters enterred from
 *                     the command line.
 * @param OutputParams Array of pointers to parameters which are processed and
 *                     ready to be used by Golang.
 * @return Error if any
*******************************************************************************/
func ProcessParameters( InputParams []string, OutputParams []*Param_t ) error {
    var err error
    FoundSubverb := false
    ParametersNoMatch := []string{}

    // We process all of the input parameters
    for i := 0; i < len( InputParams ); i++ {

        // We start by processing the subverb if there is any. It should be the
        // first element i == 0. Therefore, only one subverb is allowed.
        if i == 0 {
            for j := 0; j < len( OutputParams ); j++ {
                if OutputParams[j].Syntax == PARAM_SYNTAX_SUBVERB {
                    if FoundSubverb {
                        return errors.New("Only one subverb allowed per command")
                    }

                    FoundSubverb = true
                    // Similar to PARAM_SYNTAX_WITH_VAL, but we don't take the
                    // next parameter.
                    strVal := InputParams[i]
                    err = processOneParameter( strVal, OutputParams[j] )
                    if err != nil {
                        return err
                    }
                    OutputParams[j].Processed = true
                }
            }
            // We can skip the first element if we haven't found anything
            if FoundSubverb {
                continue
            }
        }

        // We proceed with the rest of the parameters
        for j := 0; j < len( OutputParams ); j++ {
            // We check if we have a case insensitive match
            if strings.EqualFold( InputParams[i], OutputParams[j].Name ) {

                // If the input has already been processed, we return an error
                if OutputParams[j].Processed {
                    return errors.New("Same parameter enterred more than once")
                }

                // If the parameter comes with a value, we check what it is
                if OutputParams[j].Syntax == PARAM_SYNTAX_WITH_VAL {
                    // We need to make sure that there is enough parameters to
                    //contain the value
                    if i == len( InputParams ) - 1 {
                        return errors.New("Parameter '" + InputParams[i] + "'needs a value.")
                    }

                    // Now, we have a match and we assume that the next parameter
                    // is right. We read its string value first, and then possibly
                    // convert it.
                    i++
                    strVal := InputParams[i]
                    err = processOneParameter( strVal, OutputParams[j] )
                    if err != nil {
                        return err
                    }

                } else if OutputParams[j].Syntax == PARAM_SYNTAX_STANDALONE {
                    // Here, we don't need another value, this is for boolean variables
                    if OutputParams[j].Type != PARAM_TYPE_BOOL {
                        return errors.New("The parameter type must be boolean when used in standalone mode")
                    }

                    // Because we saw the input parameter, it means that we can
                    // make this parameter true
                    OutputParams[j].Value     = true
                } else {
                    return errors.New("Invalid syntax")
                }

                // We can now break out of the loop with index j
                OutputParams[j].Processed = true
                break

            } else if j == len( OutputParams ) - 1 {
                // If there were no match for the current parameter, we add it to
                // our list of unprocessed parameters as they may be positional
                // parameters.
                ParametersNoMatch = append( ParametersNoMatch, InputParams[i] )
            }
        }
    }

    // We now process positional arguments. Indeed, these parameters will not be
    // picked up by the previous loop which looks for matches. There is an error
    // that is generated if two parameters were given the same position.
    CurrentIdx := 0
    for i := 0; i < len( ParametersNoMatch ); i++ {
        for j := 0; j < len( OutputParams ); j++ {
            if !OutputParams[j].Processed &&
                OutputParams[j].Syntax == PARAM_SYNTAX_POSITIONAL {
                if OutputParams[j].Position == CurrentIdx {
                    err = processOneParameter( ParametersNoMatch[i], OutputParams[j] )
                    if err != nil {
                        return err
                    }
                    OutputParams[j].Processed = true
                    CurrentIdx++
                    break

                } else if OutputParams[j].Position < CurrentIdx {
                    return errors.New("The same position was given to more than one positional arguments")
                }
            } else if j == len( OutputParams ) - 1 {
                // If we reach this point, it means that the parameter is invalid
                return errors.New("Parameter '" + ParametersNoMatch[i] + "' not valid.")
            }
        }
    }

    // We now process the parameters which haven't been processed yet. We simply
    // give them their default value
    for j := 0; j < len( OutputParams ); j++ {
        if !OutputParams[j].Processed {
            OutputParams[j].Value = OutputParams[j].Default
        }
    }

    return nil
}

/*******************************************************************************
 *  \brief Processes a single parameter (essentially just a casting)
 *
 * @param StringValue  Value of the parameter on the command line
 * @param Parameter    Pointer to Param_t structure
 * @return Error if any
*******************************************************************************/
func processOneParameter( StringValue string, Parameter *Param_t ) error {
    var err error
    switch Parameter.Type {
        case PARAM_TYPE_STRING:
            Parameter.Value = StringValue
        case PARAM_TYPE_INT:
            Parameter.Value, err = strconv.Atoi( StringValue )
            if err != nil {
                return err
            }
        case PARAM_TYPE_PUB_MARSHAL:
            switch strings.ToUpper( StringValue ) {
                case "PKIX":
                    Parameter.Value = PKIX
                case "PKCS1":
                    Parameter.Value = PKCS1
                default:
                    return errors.New("Public key marshalling " + StringValue + " is not supported")
            }
        case PARAM_TYPE_PRIV_MARSHAL:
            switch strings.ToUpper( StringValue ) {
                case "PKCS1":
                    Parameter.Value = PKCS1
                case "PKCS8":
                    Parameter.Value = PKCS8
                default:
                    return errors.New("Private key marshalling " + StringValue + " is not supported")
            }
        case PARAM_TYPE_BOOL:
            // If we reach this case, it means that we have found the parameter.
            // We can thus return true
            Parameter.Value = true
        case PARAM_TYPE_HEX_BYTES:
            Parameter.Value, err = hex.DecodeString( StringValue )
            if err != nil {
                return err
            }
        default:
            return errors.New( fmt.Sprintf("Type '%d' not supported", Parameter.Type) )
    }

    return err
}

/*******************************************************************************
 *  \brief Formats a string to print pretty in a block with indents.
 *
 * @param InitialStr  String to the left of the block that will dictate the indent
 * @param MainContent String containing the main content of the block
 * @param MaxWidth    Maximum width of the block
*******************************************************************************/
func C4APrettyPrintBlock( InitialStr, MainContent string, MaxWidth int  ) string {
    // We do a pretty print of the description based on a limit. That way, our
    // text lines are of equal width
    Buffer    := fmt.Sprintf( InitialStr )
    Words     := strings.Fields( MainContent )
    WordIndex := 0
    Indent    := len( strings.Trim(InitialStr, "\n") )

    // We loop until we have the full content of the description
    NbrCharacters := Indent
    for ;; {

        // If the word cannot fit on the width, we print it on its own line
        // without breaking it appart
        if Indent + len(Words[WordIndex]) >= MaxWidth {
            Buffer = fmt.Sprintf("%s%s", Buffer, Words[WordIndex])
            WordIndex++
        }

        // The second loop is for each line
        for ; NbrCharacters < MaxWidth ; {

            // We've reached the end of the line
            if WordIndex >= len(Words) {
                break
            } else if NbrCharacters + len(Words[WordIndex]) + 1 > MaxWidth {
                break
            }

            Buffer = fmt.Sprintf("%s %s", Buffer, Words[WordIndex])
            NbrCharacters += 1 + len(Words[WordIndex])
            WordIndex++
        }

        // If it's the last line, we can break the loop right now
        if WordIndex >= len(Words) {
            break
        }

        // After finishing a line, we reset the number of characters to the indenting
        NbrCharacters = Indent

        // Because we know there is another line, we add a "\n" and an indention
        Buffer = fmt.Sprintf( "%s\n%s", Buffer, strings.Repeat(" ", Indent) )
    }

    return Buffer
}