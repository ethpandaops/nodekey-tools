package generate

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/nodekey-tools/node"
	"github.com/spf13/cobra"
)

var (
	dasColumns    string
	privKeyPrefix string
	subnetCount   uint64
	columnCount   uint64
	concurrency   uint64
)

var Command = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new nodekey",
	RunE:  runGenerate,
}

func init() {
	Command.Flags().StringVar(&dasColumns, "das-columns", "", "Comma separated list of DAS columns that this node should be part of")
	Command.Flags().Uint64Var(&subnetCount, "subnet-count", 128, "Amount of data column sidecar subnets")
	Command.Flags().Uint64Var(&columnCount, "column-count", 128, "Amount of columns for DAS custody columns")
	Command.Flags().StringVar(&privKeyPrefix, "priv-key-prefix", "", "Desired prefix for the private key")
	Command.Flags().Uint64Var(&concurrency, "concurrency", uint64(runtime.NumCPU()), "Number of concurrent workers for key generation")
}

func runGenerate(cmd *cobra.Command, args []string) error {
	var privateKey *ecdsa.PrivateKey
	var err error

	if dasColumns != "" {
		// Parse string columns to uint64
		strColumns := strings.Split(dasColumns, ",")
		columns := make([]uint64, len(strColumns))
		for i, col := range strColumns {
			val, err := strconv.ParseUint(strings.TrimSpace(col), 10, 64)
			if err != nil {
				return fmt.Errorf("invalid column number '%s': %v", col, err)
			}
			columns[i] = val
		}
		fmt.Printf("Generating key for DAS columns: %v\n", columns)
		privateKey, err = node.GeneratePrivateKeyWithCustodyColumns(columns, columnCount, subnetCount, int(concurrency))
	} else if privKeyPrefix != "" {
		// Generate key with specific prefix
		privateKey, err = node.GeneratePrivateKeyWithPrefix(privKeyPrefix)
	} else {
		// Generate random key
		privateKey, err = node.GeneratePrivateKey()
	}

	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Print the private key
	privKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Printf("Private Key: %s\n", hex.EncodeToString(privKeyBytes))

	// Print the public key
	publicKey, err := node.PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate public key: %v", err)
	}
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(crypto.FromECDSAPub(publicKey)))

	// Print the node ID
	nodeID, err := node.NodeIDFromPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate node ID: %v", err)
	}
	fmt.Printf("Node ID: %s\n", nodeID.String())

	return nil
}
