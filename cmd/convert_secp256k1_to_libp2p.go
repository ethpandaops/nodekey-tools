package cmd

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"
)

var (
	ecdsaKey  string
	showExtra bool
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

var ecdsaToLibp2pCmd = &cobra.Command{
	Use:   "secp256k1-to-libp2p",
	Short: "Convert a secp256k1 private key to libp2p protobuf encoded format",
	RunE:  runEcdsaToLibp2p,
}

func init() {
	rootCmd.AddCommand(ecdsaToLibp2pCmd)
	ecdsaToLibp2pCmd.Flags().StringVar(&ecdsaKey, "key", "", "ECDSA private key in hex format")
	ecdsaToLibp2pCmd.Flags().BoolVar(&showExtra, "extra", false, "Show additional key information")
	ecdsaToLibp2pCmd.MarkFlagRequired("key")
}

func runEcdsaToLibp2p(cmd *cobra.Command, args []string) error {
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

	// Marshal the keys to bytes
	privKeyBytes, err = libp2pPrivKey.Raw()
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

	// Print the result
	fmt.Println(string(jsonOutput))

	return nil
}

// convertEcdsaToLibp2pPrivKey converts an ECDSA private key to a libp2p private key
func convertEcdsaToLibp2pPrivKey(ecdsaPrivKey *ecdsa.PrivateKey) (libp2pcrypto.PrivKey, error) {
	// Convert ECDSA private key to libp2p format
	privKeyBytes := crypto.FromECDSA(ecdsaPrivKey)

	// Create a libp2p Secp256k1 private key
	return libp2pcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
}
