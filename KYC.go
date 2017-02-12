/******************************************************************
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
******************************************************************/

///////////////////////////////////////////////////////////////////////
// Author : Jo Vercammen
// Purpose: Demo version of KYC ruling through Hyperledger platform
// First example of the KYC demo application
// Permission is not been implemented to reduce complexity for the demo application
///////////////////////////////////////////////////////////////////////

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	//"github.com/op/go-logging"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	// "github.com/errorpkg"
)

//////////////////////////////////////////////////////////////////////////////////////////////////
// The recType is a mandatory attribute. The original app was written with a single table
// in mind. The only way to know how to process a record was the 70's style 80 column punch card
// which used a record type field. The array below holds a list of valid record types.
// This could be stored on a blockchain table or an application
//////////////////////////////////////////////////////////////////////////////////////////////////
var recType = []string{"ARTINV", "USER", "BID", "AUCREQ", "POSTTRAN", "OPENAUC", "CLAUC", "XFER", "VERIFY"}

//////////////////////////////////////////////////////////////////////////////////////////////////
// The following array holds the list of tables that should be created
// The deploy/init deletes the tables and recreates them every time a deploy is invoked
//////////////////////////////////////////////////////////////////////////////////////////////////
var kycTables = []string{"IndividualTable","CompanyTable","IdentityTable","RelationshipTable","DocumentTable"}


///////////////////////////////////////////////////////////////////////////////////////
// This creates a record of the individual
// Example:
// Individual {  }
///////////////////////////////////////////////////////////////////////////////////////
type Individual struct {
	ID					string  //key
	Name				string  //key
	SecurityRole		string 
	SurName				string
	Street				string
	HouseNumber			string
	City				string
	ZipCode				string
	Country				string
	State				string
	NationalNumber		string //key
	Sex					string
	email				string 
	BlendedReputation	int
}

///////////////////////////////////////////////////////////////////////////////////////
// This creates a record of the Company
// Example:
// Company {  }
///////////////////////////////////////////////////////////////////////////////////////

type Company struct {
	ID					string //key
	CompanyName	    	string //key
	Street				string
	HouseNumber			string
	City				string
	ZipCode				string
	Country				string
	State				string
	CompanyNumber		string //key
	Type			 	string	 //(Institution,Bank,Company)
	BlendedReputation	int
	
}


///////////////////////////////////////////////////////////////////////////////////////
// This creates the related documents
// Example:
// Document {  }
///////////////////////////////////////////////////////////////////////////////////////

type Document struct {
	
	ID_OCR		string  //key  //hash of the OCR document
	ID_ORG	  	string   //hash of the original document
	Type 		string   //type of document (Utillity Bill,ID,...)
	UrlOrg		string
	UrlOcr		string
	ExpiryDate	string
	Approved	bool
}


///////////////////////////////////////////////////////////////////////////////////////
// This creates the relationship
// Example:
// Relationship {  }
///////////////////////////////////////////////////////////////////////////////////////

type Relationship struct {
	
	DocumentID	string  //key  //hash of the original document where we build the relationship with 
	Type 		string   //type of relationship (employee, shareholder, ...)
	BelongsTo	string //key 
	RelatedTo 	string
	Reputation  string  
}




///////////////////////////////////////////////////////////////////////////////////////
// This creates the relationship
// Example:
// Identity {  }
///////////////////////////////////////////////////////////////////////////////////////

type Identity struct {
	
	DocumentID	string  //key //hash of the original document where we build the relationship with 
	Type 		string   //type of document (ProofOfIdentity,ProofOfResidence,ProofOf)
	BelongsTo   string  //key
	Reputation  string  
}





/////////////////////////////////////////////////////////////////////////////////////////////////////
// A Map that holds TableNames and the number of Keys
// This information is used to dynamically Create, Update
// Replace , and Query the Ledger
// In this model all attributes in a table are strings
// The chain code does both validation
// A dummy key like 2016 in some cases is used for a query to get all rows
//
//              "IndividualTable": 		4, Key: ID, Name, Surname, NationalNumber 
//              "CompanyTable":        	3, Key: ID, CompanyName, CompanyNumber
//              "IdentityTable":     	2, Key: DocumentID, BelongsTo    
//              "RelationshipTable":  	2, Key: DocumentID, BelongsTo 
//              "DocumentTable":     	1, Key: ID_OCR
//
/////////////////////////////////////////////////////////////////////////////////////////////////////

func GetNumberOfKeys(tname string) int {
	TableMap := map[string]int{
		"IndividualTable": 		4,
		"CompanyTable":        	3,
		"IdentityTable":     	2,
		"RelationshipTable":    2,
		"DocumentTable":     	1,
	}
	return TableMap[tname]
}

//////////////////////////////////////////////////////////////
// Invoke Functions based on Function name
// The function name gets resolved to one of the following calls
// during an invoke
//
//////////////////////////////////////////////////////////////
func InvokeFunction(fname string) func(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	InvokeFunc := map[string]func(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error){
		"CreateIndividual":   CreateIndividual,
		"UpdateIndividual":   UpdateIndividual,
		"CreateCompany": 	  CreateCompany,
		"UpdateCompany":      UpdateCompany,
	}
	return InvokeFunc[fname]
}

//////////////////////////////////////////////////////////////
// Query Functions based on Function name
//
//////////////////////////////////////////////////////////////
func QueryFunction(fname string) func(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	QueryFunc := map[string]func(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error){
		"GetIndividual":         GetIndividual,
		"GetCompany":            GetCompany,
		"GetVersion":            GetVersion,
	}
	return QueryFunc[fname]
}


////////////////////////////////////////////////////////////////
//
//  Smart contract Logic
//
///////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////
// Create an Individual into the Ledger Database
//
//////////////////////////////////////////////////////////////
func CreateIndividual (stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
		var anIndividual
		
		anIndividual = Individual{args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13]}
		buff, err := CompanytoJSON(anIndividual)
		if err != nil {
			fmt.Println("CreateIndividual() : Failed Cannot create object buffer for write : ", args[1])
			return nil, errors.New("CreateIndividual(): Failed Cannot create object buffer for write : " + args[1])
		} else {
			// Update the ledger with the Buffer Data
			// err = stub.PutState(args[0], buff)
			keys := []string{args[0],args[1],args[2],args[10]}
			err = UpdateLedger(stub, "IndividualTable", keys, buff)
		if err != nil {
			fmt.Println("CreateIndividual() : write error while inserting record")
			return nil, err
		}
	return buff, err
}

//////////////////////////////////////////////////////////////
// Update an Individual from the Ledger Database
//
//////////////////////////////////////////////////////////////
func UpdateIndividual (stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
		var anIndividual
		
		anIndividual = Individual{args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13]}
		buff, err := CompanytoJSON(anIndividual)
		if err != nil {
			fmt.Println("UpdateIndividual() : Failed Cannot create object buffer for write : ", args[1])
			return nil, errors.New("UpdateIndividual(): Failed Cannot create object buffer for write : " + args[1])
		} else {
			// Update the ledger with the Buffer Data
			// err = stub.PutState(args[0], buff)
			keys := []string{args[0],args[1],args[2],args[10]}
			err = ReplaceLedgerEntry(stub, "IndividualTable", keys, buff)
		if err != nil {
			fmt.Println("UpdateIndividual() : write error while updating record")
			return nil, err
		}
	return buff, err
}

//////////////////////////////////////////////////////////////
// Create a Company into the Ledger Database
//
//////////////////////////////////////////////////////////////
func CreateCompany (stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
		var aCompany
		
		aCompany = Company{args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10]}
		buff, err := CompanytoJSON(aCompany)
		if err != nil {
			fmt.Println("CreateCompany() : Failed Cannot create object buffer for write : ", args[1])
			return nil, errors.New("CreateCompany(): Failed Cannot create object buffer for write : " + args[1])
		} else {
			// Update the ledger with the Buffer Data
			// err = stub.PutState(args[0], buff)
			keys := []string{args[0],args[1],args[8]}
			err = UpdateLedger(stub, "CompanyTable", keys, buff)
		if err != nil {
			fmt.Println("CreateCompany() : write error while inserting record")
			return nil, err
		}
	return buff, err

} 

//////////////////////////////////////////////////////////////
// Update a Company from the Ledger Database
//
//////////////////////////////////////////////////////////////
func UpdateCompany (stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
		var aCompany
		
		aCompany = Company{args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10]}
		buff, err := CompanytoJSON(aCompany)
		if err != nil {
			fmt.Println("UpdateCompany() : Failed Cannot create object buffer for write : ", args[1])
			return nil, errors.New("UpdateCompany(): Failed Cannot create object buffer for write : " + args[1])
		} else {
			// Update the ledger with the Buffer Data
			// err = stub.PutState(args[0], buff)
			keys := []string{args[0],args[1],args[8]}
			err = ReplaceLedgerEntry(stub, "CompanyTable", keys, buff)
		if err != nil {
			fmt.Println("UpdateCompany() : write error while updating record")
			return nil, err
		}
	return buff, err
}

//////////////////////////////////////////////////////////////
// Retrieve an Individual from the Ledger Database
//
//////////////////////////////////////////////////////////////
func GetIndividual (stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error

	// Get the Object and Display it
	Avalbytes, err := QueryLedger(stub, "IndividualTable", args)
	if err != nil {
		fmt.Println("GetIndividual() : Failed to Query Object ")
		jsonResp := "{\"Error\":\"Failed to get  Object Data for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	if Avalbytes == nil {
		fmt.Println("GetIndividual() : Incomplete Query Object ")
		jsonResp := "{\"Error\":\"Incomplete information about the key for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	fmt.Println("GetIndividual() : Response : Successfull -")
	return Avalbytes, nil

}

//////////////////////////////////////////////////////////////
// Retrieve a Company into the Ledger Database
//
//////////////////////////////////////////////////////////////
func GetCompany (stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error

	// Get the Object and Display it
	Avalbytes, err := QueryLedger(stub, "CompanyTable", args)
	if err != nil {
		fmt.Println("GetCompany() : Failed to Query Object ")
		jsonResp := "{\"Error\":\"Failed to get  Object Data for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	if Avalbytes == nil {
		fmt.Println("GetCompany() : Incomplete Query Object ")
		jsonResp := "{\"Error\":\"Incomplete information about the key for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	fmt.Println("GetCompany() : Response : Successfull -")
	return Avalbytes, nil
}




/////////////////////////////////////////////////////////////////////////////////
//
//   Internal framework logic  
//
////////////////////////////////////////////////////////////////////////////////



//var myLogger = logging.MustGetLogger("auction_trading")

type SimpleChaincode struct {
}

var gopath string
var ccPath string

////////////////////////////////////////////////////////////////////////////////
// Chain Code Kick-off Main function
////////////////////////////////////////////////////////////////////////////////
func main() {

//TODO: Check main kick-off


	// maximize CPU usage for maximum performance
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Println("Starting Item KYC Application chaincode BlueMix ver 0.1 Dated 2016-11-03")

	gopath = os.Getenv("GOPATH")
	if len(os.Args) == 2 && strings.EqualFold(os.Args[1], "DEV") {
		fmt.Println("----------------- STARTED IN DEV MODE -------------------- ")
		//set chaincode path for DEV MODE
		ccPath = fmt.Sprintf("%s/src/github.com/hyperledger/fabric/auction/art/artchaincode/", gopath)  //TODO
	} else {
		fmt.Println("----------------- STARTED IN NET MODE -------------------- ")
		//set chaincode path for NET MODE
		ccPath = fmt.Sprintf("%s/src/github.com/ITPeople-Blockchain/auction/art/artchaincode/", gopath) //TODO
	}

	// Start the shim -- running the fabric
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Println("Error starting KYC Application chaincode: %s", err)
	}

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SimpleChaincode - Init Chaincode implementation - The following sequence of transactions can be used to test the Chaincode
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	// TODO - Include all initialization to be complete before Invoke and Query
	// TODO - Include initial bootstrap function
	// Uses kycTables to delete tables if they exist and re-create them

	//myLogger.Info("[KYC Application] Init")
	fmt.Println("[KYC Application] Init")
	var err error

	for _, val := range kycTables {
		err = stub.DeleteTable(val)
		if err != nil {
			return nil, fmt.Errorf("Init(): DeleteTable of %s  Failed ", val)
		}
		err = InitLedger(stub, val)
		if err != nil {
			return nil, fmt.Errorf("Init(): InitLedger of %s  Failed ", val)
		}
	}
	// Update the ledger with the Application version
	err = stub.PutState("version", []byte(strconv.Itoa(1)))
	if err != nil {
		return nil, err
	}

	fmt.Println("Init() Initialization Complete  : ", args)
	return []byte("Init(): Initialization Complete"), nil
}

////////////////////////////////////////////////////////////////
// SimpleChaincode - INVOKE Chaincode implementation
// User can create individuals
// User can update individuals
// User can create Companies
// User can update Companies
////////////////////////////////////////////////////////////////

func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	var buff []byte

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Check Type of Transaction and apply business rules
	// before adding record to the block chain
	// In this version, the assumption is that args[1] specifies recType for all defined structs
	// Newer structs - the recType can be positioned anywhere and ChkReqType will check for recType
	// example:
	// ./peer chaincode invoke -l golang -n mycc -c '{"Function": "PostBid", "Args":["1111", "BID", "1", "1000", "300", "1200"]}'
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	if ChkReqType(args) == true {

		InvokeRequest := InvokeFunction(function)
		if InvokeRequest != nil {
			buff, err = InvokeRequest(stub, function, args)
		}
	} else {
		fmt.Println("Invoke() Invalid recType : ", args, "\n")
		return nil, errors.New("Invoke() : Invalid recType : " + args[0])
	}

	return buff, err
}

//////////////////////////////////////////////////////////////////////////////////////////
// SimpleChaincode - QUERY Chaincode implementation
// Client Can Query
// Sample Data
// ./peer chaincode query -l golang -n mycc -c '{"Function": "GetUser", "Args": ["4000"]}'
// ./peer chaincode query -l golang -n mycc -c '{"Function": "GetItem", "Args": ["2000"]}'
//////////////////////////////////////////////////////////////////////////////////////////

func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	var buff []byte
	fmt.Println("ID Extracted and Type = ", args[0])
	fmt.Println("Args supplied : ", args)

	if len(args) < 1 {
		fmt.Println("Query() : Include at least 1 arguments Key ")
		return nil, errors.New("Query() : Expecting Transation type and Key value for query")
	}

	QueryRequest := QueryFunction(function)
	if QueryRequest != nil {
		buff, err = QueryRequest(stub, function, args)
	} else {
		fmt.Println("Query() Invalid function call : ", function)
		return nil, errors.New("Query() : Invalid function call : " + function)
	}

	if err != nil {
		fmt.Println("Query() Object not found : ", args[0])
		return nil, errors.New("Query() : Object not found : " + args[0])
	}
	return buff, err
}

//////////////////////////////////////////////////////////////////////////////////////////
// Retrieve Auction applications version Information
// This API is to check whether application has been deployed successfully or not
// example:
// ./peer chaincode query -l golang -n mycc -c '{"Function": "GetVersion", "Args": ["version"]}'
//
//////////////////////////////////////////////////////////////////////////////////////////
func GetVersion(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if len(args) < 1 {
		fmt.Println("GetVersion() : Requires 1 argument 'version'")
		return nil, errors.New("GetVersion() : Requires 1 argument 'version'")
	}
	// Get version from the ledger
	version, err := stub.GetState(args[0])
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for version\"}"
		return nil, errors.New(jsonResp)
	}

	if version == nil {
		jsonResp := "{\"Error\":\" auction application version is invalid\"}"
		return nil, errors.New(jsonResp)
	}

	jsonResp := "{\"version\":\"" + string(version) + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)
	return version, nil
}

//////////////////////////////////////////////////////////////////////////////////////////
// Retrieve User Information
// example:
// ./peer chaincode query -l golang -n mycc -c '{"Function": "GetUser", "Args": ["100"]}'
//
//////////////////////////////////////////////////////////////////////////////////////////
func GetUser(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	var err error

	// Get the Object and Display it
	Avalbytes, err := QueryLedger(stub, "UserTable", args)
	if err != nil {
		fmt.Println("GetUser() : Failed to Query Object ")
		jsonResp := "{\"Error\":\"Failed to get  Object Data for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	if Avalbytes == nil {
		fmt.Println("GetUser() : Incomplete Query Object ")
		jsonResp := "{\"Error\":\"Incomplete information about the key for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	fmt.Println("GetUser() : Response : Successfull -")
	return Avalbytes, nil
}


/////////////////////////////////////////////////////////////////////////////////////////
// Validates The Ownership of an Asset using ItemID, OwnerID, and HashKey
//
// ./peer chaincode query -l golang -n mycc -c '{"Function": "ValidateItemOwnership", "Args": ["1000", "100", "tGEBaZuKUBmwTjzNEyd+nr/fPUASuVJAZ1u7gha5fJg="]}'
//
/////////////////////////////////////////////////////////////////////////////////////////
func ValidateItemOwnership(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	var err error

	if len(args) < 3 {
		fmt.Println("ValidateItemOwnership() : Requires 3 arguments Item#, Owner# and Key ")
		return nil, errors.New("ValidateItemOwnership() : Requires 3 arguments Item#, Owner# and Key")
	}

	// Get the Object Information
	Avalbytes, err := QueryLedger(stub, "ItemTable", []string{args[0]})
	if err != nil {
		fmt.Println("ValidateItemOwnership() : Failed to Query Object ")
		jsonResp := "{\"Error\":\"Failed to get  Object Data for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	if Avalbytes == nil {
		fmt.Println("ValidateItemOwnership() : Incomplete Query Object ")
		jsonResp := "{\"Error\":\"Incomplete information about the key for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	myItem, err := JSONtoAR(Avalbytes)
	if err != nil {
		fmt.Println("ValidateItemOwnership() : Failed to Query Object ")
		jsonResp := "{\"Error\":\"Failed to get  Object Data for " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	myKey := GetKeyValue(Avalbytes, "AES_Key")
	fmt.Println("Key String := ", myKey)

	if myKey != args[2] {
		fmt.Println("ValidateItemOwnership() : Key does not match supplied key ", args[2], " - ", myKey)
		jsonResp := "{\"Error\":\"ValidateItemOwnership() : Key does not match asset owner supplied key  " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	if myItem.CurrentOwnerID != args[1] {
		fmt.Println("ValidateItemOwnership() : ValidateItemOwnership() : Owner-Id does not match supplied ID ", args[1])
		jsonResp := "{\"Error\":\"ValidateItemOwnership() : Owner-Id does not match supplied ID " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}

	fmt.Print("ValidateItemOwnership() : Response : Successfull - \n")
	return Avalbytes, nil
}

///////////////////////////////////////////////////////////////////////
// Encryption and Decryption Section
// Images will be Encrypted and stored and the key will be part of the
// certificate that is provided to the Owner
///////////////////////////////////////////////////////////////////////

const (
	AESKeyLength = 32 // AESKeyLength is the default AES key length
	NonceSize    = 24 // NonceSize is the default NonceSize
)

///////////////////////////////////////////////////
// GetRandomBytes returns len random looking bytes
///////////////////////////////////////////////////
func GetRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

////////////////////////////////////////////////////////////
// GenAESKey returns a random AES key of length AESKeyLength
// 3 Functions to support Encryption and Decryption
// GENAESKey() - Generates AES symmetric key
// Encrypt() Encrypts a [] byte
// Decrypt() Decryts a [] byte
////////////////////////////////////////////////////////////
func GenAESKey() ([]byte, error) {
	return GetRandomBytes(AESKeyLength)
}

func PKCS5Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, pad...)
}

func PKCS5Unpad(src []byte) []byte {
	len := len(src)
	unpad := int(src[len-1])
	return src[:(len - unpad)]
}

func Decrypt(key []byte, ciphertext []byte) []byte {

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Before even testing the decryption,
	// if the text is too small, then it is incorrect
	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}

	// Get the 16 byte IV
	iv := ciphertext[:aes.BlockSize]

	// Remove the IV from the ciphertext
	ciphertext = ciphertext[aes.BlockSize:]

	// Return a decrypted stream
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt bytes from ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext
}

func Encrypt(key []byte, ba []byte) []byte {

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Empty array of 16 + ba length
	// Include the IV at the beginning
	ciphertext := make([]byte, aes.BlockSize+len(ba))

	// Slice of first 16 bytes
	iv := ciphertext[:aes.BlockSize]

	// Write 16 rand bytes to fill iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// Return an encrypted stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt bytes from ba to ciphertext
	stream.XORKeyStream(ciphertext[aes.BlockSize:], ba)

	return ciphertext
}

//////////////////////////////////////////////////////////
// JSON To args[] - return a map of the JSON string
//////////////////////////////////////////////////////////
func JSONtoArgs(Avalbytes []byte) (map[string]interface{}, error) {

	var data map[string]interface{}

	if err := json.Unmarshal(Avalbytes, &data); err != nil {
		return nil, err
	}

	return data, nil
}

//////////////////////////////////////////////////////////
// Variation of the above - return value from a JSON string
//////////////////////////////////////////////////////////

func GetKeyValue(Avalbytes []byte, key string) string {
	var dat map[string]interface{}
	if err := json.Unmarshal(Avalbytes, &dat); err != nil {
		panic(err)
	}

	val := dat[key].(string)
	return val
}

//////////////////////////////////////////////////////////
// Time and Date Comparison
// tCompare("2016-06-28 18:40:57", "2016-06-27 18:45:39")
//////////////////////////////////////////////////////////
func tCompare(t1 string, t2 string) bool {

	layout := "2006-01-02 15:04:05"
	bidTime, err := time.Parse(layout, t1)
	if err != nil {
		fmt.Println("tCompare() Failed : time Conversion error on t1")
		return false
	}

	aucCloseTime, err := time.Parse(layout, t2)
	if err != nil {
		fmt.Println("tCompare() Failed : time Conversion error on t2")
		return false
	}

	if bidTime.Before(aucCloseTime) {
		return true
	}

	return false
}






//////////////////////////////////////////////////////////
// Converts an Individual to a JSON String
//////////////////////////////////////////////////////////
func IndividualtoJSON(individual Individual) ([]byte, error) {

	ajson, err := json.Marshal(individual)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return ajson, nil
}


//////////////////////////////////////////////////////////
// Converts a Company to a JSON String
//////////////////////////////////////////////////////////
func CompanytoJSON(company Company) ([]byte, error) {

	ajson, err := json.Marshal(company)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return ajson, nil
}


//////////////////////////////////////////////////////////
// Converts a JSON String to an Individual Object 
//////////////////////////////////////////////////////////
func JSONtoIndividual(ithis []byte) (Individual, error) {

	individual := Individual{}
	err := json.Unmarshal(ithis, &individual)
	if err != nil {
		fmt.Println("JSONtoIndividual error: ", err)
		return individual, err
	}
	return individual, err
}


//////////////////////////////////////////////////////////
// Converts a JSON String to a Company Object 
//////////////////////////////////////////////////////////
func JSONtoCompany(ithis []byte) (Company, error) {

	company := Company{}
	err := json.Unmarshal(ithis, &company)
	if err != nil {
		fmt.Println("JSONtoCompany error: ", err)
		return company, err
	}
	return company, err
}



// Converts an User Object to a JSON String
//////////////////////////////////////////////////////////
func JSONtoAucReq(areq []byte) (AuctionRequest, error) {

	ar := AuctionRequest{}
	err := json.Unmarshal(areq, &ar)
	if err != nil {
		fmt.Println("JSONtoAucReq error: ", err)
		return ar, err
	}
	return ar, err
}

//////////////////////////////////////////////////////////
// Converts BID Object to JSON String
//////////////////////////////////////////////////////////
func BidtoJSON(myHand Bid) ([]byte, error) {

	ajson, err := json.Marshal(myHand)
	if err != nil {
		fmt.Println("BidtoJSON error: ", err)
		return nil, err
	}
	return ajson, nil
}

//////////////////////////////////////////////////////////
// Converts JSON String to BID Object
//////////////////////////////////////////////////////////
func JSONtoBid(areq []byte) (Bid, error) {

	myHand := Bid{}
	err := json.Unmarshal(areq, &myHand)
	if err != nil {
		fmt.Println("JSONtoBid error: ", err)
		return myHand, err
	}
	return myHand, err
}

//////////////////////////////////////////////////////////
// Converts an User Object to a JSON String
//////////////////////////////////////////////////////////
func UsertoJSON(user UserObject) ([]byte, error) {

	ajson, err := json.Marshal(user)
	if err != nil {
		fmt.Println("UsertoJSON error: ", err)
		return nil, err
	}
	fmt.Println("UsertoJSON created: ", ajson)
	return ajson, nil
}

//////////////////////////////////////////////////////////
// Converts an User Object to a JSON String
//////////////////////////////////////////////////////////
func JSONtoUser(user []byte) (UserObject, error) {

	ur := UserObject{}
	err := json.Unmarshal(user, &ur)
	if err != nil {
		fmt.Println("JSONtoUser error: ", err)
		return ur, err
	}
	fmt.Println("JSONtoUser created: ", ur)
	return ur, err
}

//////////////////////////////////////////////////////////
// Converts an Item Transaction to a JSON String
//////////////////////////////////////////////////////////
func TrantoJSON(at ItemTransaction) ([]byte, error) {

	ajson, err := json.Marshal(at)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return ajson, nil
}

//////////////////////////////////////////////////////////
// Converts an Trans Object to a JSON String
//////////////////////////////////////////////////////////
func JSONtoTran(areq []byte) (ItemTransaction, error) {

	at := ItemTransaction{}
	err := json.Unmarshal(areq, &at)
	if err != nil {
		fmt.Println("JSONtoTran error: ", err)
		return at, err
	}
	return at, err
}

//////////////////////////////////////////////
// Validates an ID for Well Formed
//////////////////////////////////////////////

func validateID(id string) error {
	// Validate UserID is an integer

	_, err := strconv.Atoi(id)
	if err != nil {
		return errors.New("validateID(): User ID should be an integer")
	}
	return nil
}


////////////////////////////////////////////////////////////////////////////
// Validate if the User Information Exists
// in the block-chain
////////////////////////////////////////////////////////////////////////////
func ValidateMember(stub shim.ChaincodeStubInterface, owner string) ([]byte, error) {

	// Get the Item Objects and Display it
	// Avalbytes, err := stub.GetState(owner)
	args := []string{owner, "USER"}
	Avalbytes, err := QueryLedger(stub, "UserTable", args)

	if err != nil {
		fmt.Println("ValidateMember() : Failed - Cannot find valid owner record for ART  ", owner)
		jsonResp := "{\"Error\":\"Failed to get Owner Object Data for " + owner + "\"}"
		return nil, errors.New(jsonResp)
	}

	if Avalbytes == nil {
		fmt.Println("ValidateMember() : Failed - Incomplete owner record for ART  ", owner)
		jsonResp := "{\"Error\":\"Failed - Incomplete information about the owner for " + owner + "\"}"
		return nil, errors.New(jsonResp)
	}

	fmt.Println("ValidateMember() : Validated Item Owner:\n", owner)
	return Avalbytes, nil
}

////////////////////////////////////////////////////////////////////////////
// Validate if the User Information Exists
// in the block-chain
////////////////////////////////////////////////////////////////////////////
func ValidateItemSubmission(stub shim.ChaincodeStubInterface, artId string) ([]byte, error) {

	// Get the Item Objects and Display it
	args := []string{artId, "ARTINV"}
	Avalbytes, err := QueryLedger(stub, "ItemTable", args)
	if err != nil {
		fmt.Println("ValidateItemSubmission() : Failed - Cannot find valid owner record for ART  ", artId)
		jsonResp := "{\"Error\":\"Failed to get Owner Object Data for " + artId + "\"}"
		return nil, errors.New(jsonResp)
	}

	if Avalbytes == nil {
		fmt.Println("ValidateItemSubmission() : Failed - Incomplete owner record for ART  ", artId)
		jsonResp := "{\"Error\":\"Failed - Incomplete information about the owner for " + artId + "\"}"
		return nil, errors.New(jsonResp)
	}

	//fmt.Println("ValidateItemSubmission() : Validated Item Owner:", Avalbytes)
	return Avalbytes, nil
}*/

////////////////////////////////////////////////////////////////////////////
// Open a Ledgers if one does not exist
// These ledgers will be used to write /  read data
// Use names are listed in kycTables {}
// THIS FUNCTION REPLACES ALL THE INIT Functions below
//  - InitUserReg()
//  - InitAucReg()
//  - InitBidReg()
//  - InitItemReg()
//  - InitItemMaster()
//  - InitTransReg()
//  - InitAuctionTriggerReg()
//  - etc. etc.
////////////////////////////////////////////////////////////////////////////
func InitLedger(stub shim.ChaincodeStubInterface, tableName string) error {

    //TODO: Table Creation Function.....


	// Generic Table Creation Function - requires Table Name and Table Key Entry
	// Create Table - Get number of Keys the tables supports
	// This version assumes all Keys are String and the Data is Bytes
	// This Function can replace all other InitLedger function in this app such as InitItemLedger()

	nKeys := GetNumberOfKeys(tableName)
	if nKeys < 1 {
		fmt.Println("Atleast 1 Key must be provided \n")
		fmt.Println("KYC Application: Failed creating Table ", tableName)
		return errors.New("KYC Application: Failed creating Table " + tableName)
	}

	var columnDefsForTbl []*shim.ColumnDefinition

	for i := 0; i < nKeys; i++ {
		columnDef := shim.ColumnDefinition{Name: "keyName" + strconv.Itoa(i), Type: shim.ColumnDefinition_STRING, Key: true}
		columnDefsForTbl = append(columnDefsForTbl, &columnDef)
	}

	columnLastTblDef := shim.ColumnDefinition{Name: "Details", Type: shim.ColumnDefinition_BYTES, Key: false}
	columnDefsForTbl = append(columnDefsForTbl, &columnLastTblDef)

	// Create the Table (Nil is returned if the Table exists or if the table is created successfully
	err := stub.CreateTable(tableName, columnDefsForTbl)

	if err != nil {
		fmt.Println("KYC Application: Failed creating Table ", tableName)
		return errors.New("KYC Application: Failed creating Table " + tableName)
	}

	return err
}

////////////////////////////////////////////////////////////////////////////
// Open a User Registration Table if one does not exist
// Register users into this table
////////////////////////////////////////////////////////////////////////////
func UpdateLedger(stub shim.ChaincodeStubInterface, tableName string, keys []string, args []byte) error {

	nKeys := GetNumberOfKeys(tableName)
	if nKeys < 1 {
		fmt.Println("Atleast 1 Key must be provided \n")
	}

	var columns []*shim.Column

	for i := 0; i < nKeys; i++ {
		col := shim.Column{Value: &shim.Column_String_{String_: keys[i]}}
		columns = append(columns, &col)
	}

	lastCol := shim.Column{Value: &shim.Column_Bytes{Bytes: []byte(args)}}
	columns = append(columns, &lastCol)

	row := shim.Row{columns}
	ok, err := stub.InsertRow(tableName, row)
	if err != nil {
		return fmt.Errorf("UpdateLedger: InsertRow into "+tableName+" Table operation failed. %s", err)
	}
	if !ok {
		return errors.New("UpdateLedger: InsertRow into " + tableName + " Table failed. Row with given key " + keys[0] + " already exists")
	}

	fmt.Println("UpdateLedger: InsertRow into ", tableName, " Table operation Successful. ")
	return nil
}

////////////////////////////////////////////////////////////////////////////
// Open a User Registration Table if one does not exist
// Register users into this table
////////////////////////////////////////////////////////////////////////////
func DeleteFromLedger(stub shim.ChaincodeStubInterface, tableName string, keys []string) error {
	var columns []shim.Column

	//nKeys := GetNumberOfKeys(tableName)
	nCol := len(keys)
	if nCol < 1 {
		fmt.Println("Atleast 1 Key must be provided \n")
		return errors.New("DeleteFromLedger failed. Must include at least key values")
	}

	for i := 0; i < nCol; i++ {
		colNext := shim.Column{Value: &shim.Column_String_{String_: keys[i]}}
		columns = append(columns, colNext)
	}

	err := stub.DeleteRow(tableName, columns)
	if err != nil {
		return fmt.Errorf("DeleteFromLedger operation failed. %s", err)
	}

	fmt.Println("DeleteFromLedger: DeleteRow from ", tableName, " Table operation Successful. ")
	return nil
}

////////////////////////////////////////////////////////////////////////////
// Replaces the Entry in the Ledger
//
////////////////////////////////////////////////////////////////////////////
func ReplaceLedgerEntry(stub shim.ChaincodeStubInterface, tableName string, keys []string, args []byte) error {

	nKeys := GetNumberOfKeys(tableName)
	if nKeys < 1 {
		fmt.Println("Atleast 1 Key must be provided \n")
	}

	var columns []*shim.Column

	for i := 0; i < nKeys; i++ {
		col := shim.Column{Value: &shim.Column_String_{String_: keys[i]}}
		columns = append(columns, &col)
	}

	lastCol := shim.Column{Value: &shim.Column_Bytes{Bytes: []byte(args)}}
	columns = append(columns, &lastCol)

	row := shim.Row{columns}
	ok, err := stub.ReplaceRow(tableName, row)
	if err != nil {
		return fmt.Errorf("ReplaceLedgerEntry: Replace Row into "+tableName+" Table operation failed. %s", err)
	}
	if !ok {
		return errors.New("ReplaceLedgerEntry: Replace Row into " + tableName + " Table failed. Row with given key " + keys[0] + " already exists")
	}

	fmt.Println("ReplaceLedgerEntry: Replace Row in ", tableName, " Table operation Successful. ")
	return nil
}

////////////////////////////////////////////////////////////////////////////
// Query a User Object by Table Name and Key
////////////////////////////////////////////////////////////////////////////
func QueryLedger(stub shim.ChaincodeStubInterface, tableName string, args []string) ([]byte, error) {

	var columns []shim.Column
	nCol := GetNumberOfKeys(tableName)
	for i := 0; i < nCol; i++ {
		colNext := shim.Column{Value: &shim.Column_String_{String_: args[i]}}
		columns = append(columns, colNext)
	}

	row, err := stub.GetRow(tableName, columns)
	fmt.Println("Length or number of rows retrieved ", len(row.Columns))

	if len(row.Columns) == 0 {
		jsonResp := "{\"Error\":\"Failed retrieving data " + args[0] + ". \"}"
		fmt.Println("Error retrieving data record for Key = ", args[0], "Error : ", jsonResp)
		return nil, errors.New(jsonResp)
	}

	//fmt.Println("User Query Response:", row)
	//jsonResp := "{\"Owner\":\"" + string(row.Columns[nCol].GetBytes()) + "\"}"
	//fmt.Println("User Query Response:%s\n", jsonResp)
	Avalbytes := row.Columns[nCol].GetBytes()

	// Perform Any additional processing of data
	fmt.Println("QueryLedger() : Successful - Proceeding to ProcessRequestType ")
	err = ProcessQueryResult(stub, Avalbytes, args)
	if err != nil {
		fmt.Println("QueryLedger() : Cannot create object  : ", args[1])
		jsonResp := "{\"QueryLedger() Error\":\" Cannot create Object for key " + args[0] + "\"}"
		return nil, errors.New(jsonResp)
	}
	return Avalbytes, nil
}








////////////////////////////////////////////////////////////////////////////
// Get a List of Rows based on query criteria from the OBC
//
////////////////////////////////////////////////////////////////////////////
func GetList(stub shim.ChaincodeStubInterface, tableName string, args []string) ([]shim.Row, error) {
	var columns []shim.Column

	nKeys := GetNumberOfKeys(tableName)
	nCol := len(args)
	if nCol < 1 {
		fmt.Println("Atleast 1 Key must be provided \n")
		return nil, errors.New("GetList failed. Must include at least key values")
	}

	for i := 0; i < nCol; i++ {
		colNext := shim.Column{Value: &shim.Column_String_{String_: args[i]}}
		columns = append(columns, colNext)
	}

	rowChannel, err := stub.GetRows(tableName, columns)
	if err != nil {
		return nil, fmt.Errorf("GetList operation failed. %s", err)
	}
	var rows []shim.Row
	for {
		select {
		case row, ok := <-rowChannel:
			if !ok {
				rowChannel = nil
			} else {
				rows = append(rows, row)
				//If required enable for debugging
				//fmt.Println(row)
			}
		}
		if rowChannel == nil {
			break
		}
	}

	fmt.Println("Number of Keys retrieved : ", nKeys)
	fmt.Println("Number of rows retrieved : ", len(rows))
	return rows, nil
}


