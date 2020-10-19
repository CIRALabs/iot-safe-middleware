/*******************************************************************************
 * Title:       file_utils.go
 * Author:      O. C.
 * Project:     Crypto4A's common functions (common)
 * Description: The current file implements different functionalities related to
 *              file management. It includes saving data to a file, as well as
 *              retrieving information from the file.
 * Functions:
 *  - IsFile:               Checks file existence
 *  - IsDir:                Checks directory existence
 *  - IsEmpty:               Checks if directory is empty
 *  - WriteBytesToFile:     Writes array of bytes to file
 *  - WriteToJSON:          Write any structure to JSON file
 *  - WritePEMBlockToFile:  Writes PEM structure to file
 *  - ReadBytesFromFile:    Reads and return content of file in a byte array
 *  - ReadFromJSON:         Read JSON file into any structure (if it matches)
 *  - ReadPEMBlockFromFile: Retrieves content of a PEM structure from file
*******************************************************************************/

package common

import(
    "io"
    "os"
    "fmt"
    "errors"
    "strings"
    "io/ioutil"
    "encoding/pem"
    "encoding/json"
    "path/filepath"
)

/*******************************************************************************
 *  \brief Verifies if a file exists
 *
 * @param FileName String indicating the name of the file
 * @return Bool value which is true if the file exists
*******************************************************************************/
func IsFile( FileName string ) bool {
    // Check if file exists. If it does, we return nothing
    _, err := os.Stat( FileName )
    if os.IsNotExist( err ) {
        return false
    }

    return true
}

/*******************************************************************************
 *  \brief Verifies if file is a directory
 *
 * @param DirNam String indicating the name of the directory
 * @return Bool value which is true if the file exists
*******************************************************************************/
func IsDir( DirName string ) bool {
    // Check if file exists. If it does, we return nothing
    info, err := os.Stat( DirName )
    if os.IsNotExist( err ) {
        return false
    } else if !info.IsDir() {
        return false
    }

    return true
}

/*******************************************************************************
 *  \brief Checks if directory is empty
 *
 * This code was taken from https://stackoverflow.com/questions/30697324/how-to-check-if-directory-on-path-is-empty
 * @param Name   Name of directory
 * @return True if directory is empty, false otherwise
 * @return Error status
*******************************************************************************/
func IsEmpty( Name string ) (bool, error) {
    f, err := os.Open( Name )
    if err != nil {
        return false, err
    }
    defer f.Close()

    _, err = f.Readdirnames( 1 ) // Or f.Readdir(1)
    if err == io.EOF {
        return true, nil
    }
    return false, err // Either not empty or error, suits both cases
}

/*******************************************************************************
 *  \brief Writes array of bytes to a file
 *
 * @param FileContent Array of bytes containing the content of the file
 * @param FileName    String indicating the name of the file
 * @param Force       Bool which will overwrite an existent file if true.
 * @return Error if any
*******************************************************************************/
func WriteBytesToFile( FileContent []byte, FileName string, Force bool ) error {

    // If the file exists, we issue an error
    if IsFile( FileName ) {
        if !Force {
            return errors.New( fmt.Sprintf("File %s already exists. Use the '-f' flag to overwrite existing files.", FileName) )
        }
        // fmt.Println("Writing over existing file")
    }

    // Transorming the filename into an absolute path to remove any
    // ambiguity
    FileName, err  := filepath.Abs( FileName )
    if err != nil {
        return err
    }
    FileObj, err := os.Create( FileName )
    if err != nil {
        return err
    }

    // We write the file content to the file
    NbrBytesWritten, err := FileObj.Write( FileContent )
    if err != nil {
        return err
    // This is probably redundant
    } else if len( FileContent ) != NbrBytesWritten {
        return errors.New( "Error writing to file" )
    }

    // We commit the content of the file to stable memory location
    err = FileObj.Sync()
    if err != nil {
        return err
    }
    return FileObj.Close()
}

/*******************************************************************************
 *  \brief Writes any structure into JSON format for better readability
 *
 * @param OutputFile String representing output file name
 * @param Interface  Pointer to custodian list structure
 * @param Force       Bool which will overwrite an existent file if true.
 * @return Error if any
*******************************************************************************/
func WriteToJSON( OutputFile string, Interface interface{}, Force bool ) error {

    // We make sure we are writing to a JSON file
    if !strings.Contains( OutputFile, ".json" ) {
        return errors.New( "Json file must end with .json" )
    }

    // If the file exists, we issue an error
    if IsFile( OutputFile ) {
        if !Force {
            return errors.New( fmt.Sprintf("File %s already exists. Use the '-f' flag to overwrite existing files.", OutputFile) )
        }
        // fmt.Println("Writing over existing file")
    }

    // We marshal the structure with spaces
    JSONContent, err := json.MarshalIndent(Interface, "", " ")
    if err != nil {
        return err
    }

    // Write to file
    err = ioutil.WriteFile( OutputFile, JSONContent, 0644 )
    return err
}

/*******************************************************************************
 *  \brief Writes a PEMBlock to a file
 *
 * @param PEMBlock Pointer to PEM block
 * @param FileName String indicating the name of the file
 * @param Force    Bool which will overwrite an existent file if true.
 * @return Error status
*******************************************************************************/
func WritePEMBlockToFile( PEMBlock *pem.Block, FileName string, Force bool ) error {

    // We convert the PEM Block into a byte array
    FileContent := pem.EncodeToMemory( PEMBlock )

    // We write to the file
    return WriteBytesToFile( FileContent, FileName, Force )
}

/*******************************************************************************
 *  \brief Reads the content of a file and returns a byte array
 *
 * @param FileName String indicating the name of the file
 * @return Array of bytes containing the content of the file
 * @return Error status
*******************************************************************************/
func ReadBytesFromFile( FileName string ) ([]byte, error) {
    info, err := os.Stat( FileName )

    // If the file doesn't exist, we issue an error
    if os.IsNotExist( err ) {
        return nil, errors.New( fmt.Sprintf("File %s doesn't exist", FileName) )

    // If the file is a directory, we issue an error
    } else if info.IsDir() {
        return nil, errors.New( "Expected file, got directory" )

    // Any other error we return it
    } else if err != nil {
        return nil, err
    }

    return ioutil.ReadFile( FileName )
}

/*******************************************************************************
 *  \brief Reads any structure from JSON format into the interface it was given
 *
 * @param FileName  String representing the json file
 * @param Interface Empty interface that will contain the content of the JSON
 *                  file
 * @return Error status
*******************************************************************************/
func ReadFromJSON( FileName string, Interface interface{} ) error {
    FileContent, err := ReadBytesFromFile( FileName )
    if err != nil {
        return err
    }

    err = json.Unmarshal( FileContent, &Interface )
    if err != nil {
        return err
    }

    return nil
}

/*******************************************************************************
 *  \brief Retrieves a PEM block saved in a file
 *
 * @param  FileName String indicating the name of the file
 * @return Pointer to PEM block
 * @return Error status
*******************************************************************************/
func ReadPEMBlockFromFile( FileName string ) (*pem.Block, error) {
    // We retrieve the content of the file. 'ReadBytesFromFile' will go through
    // some sanity checks so we don't have to worry about this
    FileContent, err := ReadBytesFromFile( FileName )

    if err != nil {
        return nil, err
    } else {
        PEMBlock, rest := pem.Decode( FileContent )
        if len(rest) != 0 {
            return nil, errors.New("Error reading PEM block")
        } else if PEMBlock == nil {
            return nil, errors.New("Error reading PEM block")
        }
        return PEMBlock, nil
    }
}