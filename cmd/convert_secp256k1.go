package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/scrypt"
)

var (
	ecdsaKey         string
	showExtra        bool
	keystorePassword string
)

type LibP2PKeyOutput struct {
	ID         string                `json:"id"`
	PubKey     string                `json:"pubKey"`
	PrivateKey string                `json:"privKey"`
	Extra      *LibP2PKeyExtraOutput `json:"extra,omitempty"`
}

type LibP2PKeyExtraOutput struct {
	Type       string `json:"type"`
	PubKeyRaw  string `json:"pubKeyRaw"`
	PrivKeyRaw string `json:"privKeyRaw"`
	PubKeyHex  string `json:"pubKeyRawHex"`
	PrivKeyHex string `json:"privKeyRawHex"`
}

type KeystoreOutput struct {
	Crypto struct {
		KDF struct {
			Function string `json:"function"`
			Params   struct {
				DKLen int    `json:"dklen"`
				N     int    `json:"n"`
				P     int    `json:"p"`
				R     int    `json:"r"`
				Salt  string `json:"salt"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"kdf"`
		Checksum struct {
			Function string            `json:"function"`
			Params   map[string]string `json:"params"`
			Message  string            `json:"message"`
		} `json:"checksum"`
		Cipher struct {
			Function string `json:"function"`
			Params   struct {
				IV string `json:"iv"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"cipher"`
	} `json:"crypto"`
	Pubkey  string `json:"pubkey"`
	UUID    string `json:"uuid"`
	Version int    `json:"version"`
}

var convertKeyFormatCmd = &cobra.Command{
	Use:   "convert-secp256k1",
	Short: "Convert a secp256k1 private key to different formats",
	RunE:  runConvertKeyFormat,
}

func init() {
	rootCmd.AddCommand(convertKeyFormatCmd)
	convertKeyFormatCmd.Flags().StringVar(&ecdsaKey, "key", "", "ECDSA private key in hex format")
	convertKeyFormatCmd.Flags().BoolVar(&showExtra, "extra", false, "Show additional key information")
	convertKeyFormatCmd.Flags().StringVar(&outputFormat, "output-format", "libp2p", "Output format: 'libp2p', 'binary', or 'keystore'")
	convertKeyFormatCmd.Flags().StringVar(&outputFile, "output-file", "", "Output file path (defaults to key value if not specified)")
	convertKeyFormatCmd.Flags().StringVar(&keystorePassword, "keystore-password", "INSECUREPASSWORD", "Password for keystore output")
	convertKeyFormatCmd.MarkFlagRequired("key")
}

func runConvertKeyFormat(cmd *cobra.Command, args []string) error {
	// Remove 0x prefix if present
	ecdsaKey = strings.TrimPrefix(ecdsaKey, "0x")

	// Decode the ECDSA private key
	privKeyBytes, err := hex.DecodeString(ecdsaKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %v", err)
	}

	// Parse the ECDSA private key
	ecdsaPrivKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse ECDSA private key: %v", err)
	}

	// Handle different output formats
	switch outputFormat {
	case "libp2p":
		// Convert ECDSA private key to libp2p private key
		libp2pPrivKey, err := convertEcdsaToLibp2pPrivKey(ecdsaPrivKey)
		if err != nil {
			return fmt.Errorf("failed to convert to libp2p private key: %v", err)
		}

		// Get the libp2p public key
		libp2pPubKey := libp2pPrivKey.GetPublic()

		// Get the peer ID from the public key
		peerID, err := libp2ppeer.IDFromPublicKey(libp2pPubKey)
		if err != nil {
			return fmt.Errorf("failed to generate peer ID: %v", err)
		}

		return handleLibp2pOutput(libp2pPrivKey, libp2pPubKey, peerID)
	case "binary":
		return handleBinaryOutput(ecdsaPrivKey)
	case "keystore":
		if keystorePassword == "INSECUREPASSWORD" {
			fmt.Println("Info: Using insecure default password for keystore output: INSECUREPASSWORD")
		}
		// Convert ECDSA private key to libp2p private key
		libp2pPrivKey, err := convertEcdsaToLibp2pPrivKey(ecdsaPrivKey)
		if err != nil {
			return fmt.Errorf("failed to convert to libp2p private key: %v", err)
		}

		// Get the libp2p public key
		libp2pPubKey := libp2pPrivKey.GetPublic()
		return handleKeystoreOutput(libp2pPrivKey, libp2pPubKey, keystorePassword)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
}

func handleLibp2pOutput(libp2pPrivKey libp2pcrypto.PrivKey, libp2pPubKey libp2pcrypto.PubKey, peerID libp2ppeer.ID) error {
	// Marshal the keys to bytes
	privKeyBytes, err := libp2pPrivKey.Raw()
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	pubKeyBytes, err := libp2pPubKey.Raw()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Encode the keys to base64
	privKeyEncoded := base64.StdEncoding.EncodeToString(privKeyBytes)
	pubKeyEncoded := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Encode the keys to hex
	privKeyHex := hex.EncodeToString(privKeyBytes)
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	// Get the protobuf-encoded versions of the keys
	privKeyProto, err := libp2pcrypto.MarshalPrivateKey(libp2pPrivKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key to protobuf: %v", err)
	}

	pubKeyProto, err := libp2pcrypto.MarshalPublicKey(libp2pPubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key to protobuf: %v", err)
	}

	// Encode the protobuf keys to base64
	privKeyProtoEncoded := base64.StdEncoding.EncodeToString(privKeyProto)
	pubKeyProtoEncoded := base64.StdEncoding.EncodeToString(pubKeyProto)

	// Create the output
	output := LibP2PKeyOutput{
		ID:         peerID.String(),
		PubKey:     pubKeyProtoEncoded,
		PrivateKey: privKeyProtoEncoded,
	}

	// Only include extra fields if the --extra flag is provided
	if showExtra {
		output.Extra = &LibP2PKeyExtraOutput{
			Type:       libp2pPrivKey.Type().String(),
			PubKeyRaw:  pubKeyEncoded,
			PrivKeyRaw: privKeyEncoded,
			PubKeyHex:  pubKeyHex,
			PrivKeyHex: privKeyHex,
		}
	}

	// Marshal to JSON
	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	return writeOutput(jsonOutput)
}

func handleBinaryOutput(ecdsaPrivKey *ecdsa.PrivateKey) error {
	// Get the binary representation of the ECDSA private key
	privKeyBytes := crypto.FromECDSA(ecdsaPrivKey)

	return writeOutput(privKeyBytes)
}

func handleKeystoreOutput(libp2pPrivKey libp2pcrypto.PrivKey, libp2pPubKey libp2pcrypto.PubKey, password string) error {
	// Marshal the private key to bytes
	privKeyBytes, err := libp2pcrypto.MarshalPrivateKey(libp2pPrivKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	// Marshal the public key to bytes
	pubKeyBytes, err := libp2pcrypto.MarshalPublicKey(libp2pPubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Create a new keystore output
	keystore := KeystoreOutput{}
	keystore.Version = 1
	keystore.UUID = uuid.New().String()
	keystore.Pubkey = hex.EncodeToString(pubKeyBytes)

	// Encryption parameters
	scryptN := 262144
	scryptP := 1
	scryptR := 8
	dkLen := 32

	// Generate a random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}

	// Derive the encryption key using scrypt
	derivedKey, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, dkLen)
	if err != nil {
		return fmt.Errorf("failed to derive encryption key: %v", err)
	}

	// Generate a random IV for AES-CTR
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV: %v", err)
	}

	// Encrypt the private key using AES-CTR
	block, err := aes.NewCipher(derivedKey[:16])
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}
	cipherText := make([]byte, len(privKeyBytes))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText, privKeyBytes)

	// Calculate the checksum
	mac := sha256.Sum256(append(derivedKey[16:32], cipherText...))

	// Populate the keystore structure
	keystore.Crypto.KDF.Function = "scrypt"
	keystore.Crypto.KDF.Params.DKLen = dkLen
	keystore.Crypto.KDF.Params.N = scryptN
	keystore.Crypto.KDF.Params.P = scryptP
	keystore.Crypto.KDF.Params.R = scryptR
	keystore.Crypto.KDF.Params.Salt = hex.EncodeToString(salt)
	keystore.Crypto.KDF.Message = ""

	keystore.Crypto.Cipher.Function = "aes-128-ctr"
	keystore.Crypto.Cipher.Params.IV = hex.EncodeToString(iv)
	keystore.Crypto.Cipher.Message = hex.EncodeToString(cipherText)

	keystore.Crypto.Checksum.Function = "sha256"
	keystore.Crypto.Checksum.Params = make(map[string]string)
	keystore.Crypto.Checksum.Message = hex.EncodeToString(mac[:])

	// Marshal to JSON
	jsonOutput, err := json.MarshalIndent(keystore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	return writeOutput(jsonOutput)
}

func writeOutput(data []byte) error {
	// Determine output file path
	outputPath := outputFile
	if outputPath == "" {
		outputPath = ecdsaKey
		if outputFormat == "libp2p" {
			outputPath += ".libp2p.json"
		} else if outputFormat == "binary" {
			outputPath += ".bin"
		}
	}

	// If output file is specified, write to file
	if outputPath != "" {
		// Ensure directory exists
		dir := filepath.Dir(outputPath)
		if dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %v", err)
			}
		}

		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
		fmt.Printf("Output written to %s\n", outputPath)
	} else {
		// Otherwise print to stdout
		if outputFormat == "libp2p" {
			fmt.Println(string(data))
		} else {
			fmt.Printf("%x\n", data)
		}
	}

	return nil
}

// convertEcdsaToLibp2pPrivKey converts an ECDSA private key to a libp2p private key
func convertEcdsaToLibp2pPrivKey(ecdsaPrivKey *ecdsa.PrivateKey) (libp2pcrypto.PrivKey, error) {
	// Convert ECDSA private key to libp2p format
	privKeyBytes := crypto.FromECDSA(ecdsaPrivKey)

	// Create a libp2p Secp256k1 private key
	return libp2pcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
}
