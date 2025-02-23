package main

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

// Define the request body struct
type RequestBody struct {
	PublicKey  string `json:"public_key"`
	OSVersion  string `json:"os_version"`
	AppVersion string `json:"app_version"`
	UUID       string `json:"uuid"`
}

// Define the response struct
type ResponseBody struct {
	Config string `json:"config"`
}

type Config struct {
	Containers []Container `json:"containers"`
}

type Container struct {
	AWG AWG `json:"awg"`
}

type AWG struct {
	LastConfig string `json:"last_config"`
}

type LastConfig struct {
	Config map[string]interface{} `json:"config"`
}

// Define the structure for the parsed JSON
type DecodedData struct {
	APIEndpoint string `json:"api_endpoint"`
	APIKey      string `json:"api_key"`
}

func main() {
	// Define a string flag named "key" with a default value and a description
	key := flag.String("key", "", "The key string to process")

	// Parse the command-line arguments
	flag.Parse()

	// Check if the "key" parameter was provided
	if key == nil || *key == "" {
		fmt.Println("Error: The -key parameter is required.")
		flag.Usage() // Print usage information
		return
	}

	decoded, err := decodeAndParse(*key)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Example URL and API key
	url := decoded.APIEndpoint
	apiKey := decoded.APIKey

	pubKey, privateKey, err := GenerateX25519KeyPair()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Prepare the request body
	requestBody := RequestBody{
		PublicKey:  pubKey,
		OSVersion:  "macOS",
		AppVersion: "4.8.2.3",
		UUID:       uuid.New().String(),
	}

	// // Prepare a variable to store the response
	var responseBody ResponseBody

	// Call the sendPostRequest function
	err = sendPostRequest(url, requestBody, apiKey, &responseBody)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	decodedConfig, err := decode(responseBody.Config)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var config Config
	err = json.Unmarshal(decodedConfig, &config)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var lastConfig map[string]interface{}
	err = json.Unmarshal([]byte(config.Containers[0].AWG.LastConfig), &lastConfig)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Print the parsed response
	fmt.Printf("\nPrivate key: %+v\n", privateKey)

	resp := strings.Replace(lastConfig["config"].(string), "$WIREGUARD_CLIENT_PRIVATE_KEY", privateKey, -1)
	fmt.Printf("\nResponse: \n%+v\n", resp)
}

// sendPostRequest sends a POST request to the specified URL with a JSON body and Authorization header.
// It parses the response into the provided result struct.
func sendPostRequest(url string, body interface{}, apiKey string, response interface{}) error {
	// Validate input parameters
	if url == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	if apiKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	// Serialize the body into JSON
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to serialize request body: %v", err)
	}

	// Create a new HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Api-Key "+apiKey)

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Check the HTTP response status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected HTTP status code: %d, Response: %s", resp.StatusCode, string(bodyBytes))
	}

	// Read and parse the response body into the result struct
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	err = json.Unmarshal(respBody, response)
	if err != nil {
		return fmt.Errorf("failed to parse response JSON: %v", err)
	}

	return nil
}

// GenerateX25519KeyPair generates a private and public key pair for X25519.
func GenerateX25519KeyPair() (privateKeyBase64 string, publicKeyBase64 string, err error) {
	// Step 1: Generate a random private key (32 bytes)
	privateKey := make([]byte, curve25519.ScalarSize)
	_, err = rand.Read(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	// Clamp the private key according to X25519 requirements
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Step 2: Compute the corresponding public key
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("failed to compute public key: %v", err)
	}

	// Step 3: Encode keys in Base64 for readability
	privateKeyBase64 = base64.StdEncoding.EncodeToString(privateKey)
	publicKeyBase64 = base64.StdEncoding.EncodeToString(publicKey)

	return privateKeyBase64, publicKeyBase64, nil
}

// decodeAndParse decodes a Base64 (URL-safe) string, decompresses it using zlib,
// and parses the result into a JSON object with api_endpoint and api_key fields.
func decodeAndParse(encodedString string) (*DecodedData, error) {
	decompressedBytes, err := decode(encodedString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %v", err)
	}

	// Step 3: Parse the decompressed data into a JSON object
	var decodedData DecodedData
	err = json.Unmarshal(decompressedBytes, &decodedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return &decodedData, nil
}

func decode(encodedString string) ([]byte, error) {
	encodedString = strings.Replace(encodedString, "vpn://", "", -1)

	// Step 1: Decode the Base64 (URL-safe) string
	decodedBytes, err := base64.URLEncoding.DecodeString(encodedString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base64 string: %v", err)
	}

	// Step 2: Decompress the decoded bytes using zlib
	zlibReader, err := zlib.NewReader(bytes.NewReader(decodedBytes[4:]))
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %v", err)
	}
	defer zlibReader.Close()

	decompressedBytes, err := io.ReadAll(zlibReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %v", err)
	}

	return decompressedBytes, nil
}
