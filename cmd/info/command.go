package info

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethpandaops/nodekey-tools/node"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var (
	fromPrivKey  string
	fromNodeId   string
	cscCount     uint64
	subnetCount  uint64
	columnCount  uint64
	outputFormat string
)

var Command = &cobra.Command{
	Use:   "info",
	Short: "Show information about a nodekey",
	RunE:  runInfo,
}

func init() {
	Command.Flags().StringVar(&fromPrivKey, "priv-key", "", "Private key in hex format")
	Command.Flags().StringVar(&fromNodeId, "node-id", "", "Node ID")
	Command.Flags().Uint64Var(&subnetCount, "subnet-count", 128, "Amount of data column sidecar subnets")
	Command.Flags().Uint64Var(&columnCount, "column-count", 128, "Amount of columns for DAS custody columns")
	Command.Flags().Uint64Var(&cscCount, "custody-column-count", 8, "Number of columns that should be custodied")
	Command.Flags().StringVar(&outputFormat, "output-format", "text", "Output format (text/json)")
}

func runInfo(cmd *cobra.Command, args []string) error {
	var nodeID enode.ID

	if fromPrivKey == "" && fromNodeId == "" {
		return fmt.Errorf("either private key or node ID must be provided")
	}

	if fromPrivKey != "" {
		// Remove 0x prefix if present
		fromPrivKey = strings.TrimPrefix(fromPrivKey, "0x")

		// Decode private key
		privKeyBytes, err := hex.DecodeString(fromPrivKey)
		if err != nil {
			return fmt.Errorf("failed to decode private key: %v", err)
		}

		privateKey, err := crypto.ToECDSA(privKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}

		// Get node ID
		var err2 error
		nodeID, err2 = node.NodeIDFromPrivateKey(privateKey)
		if err2 != nil {
			return fmt.Errorf("failed to generate node ID: %v", err2)
		}
	} else {
		// Parse node ID
		var err error
		nodeID, err = enode.ParseID(fromNodeId)
		if err != nil {
			return fmt.Errorf("failed to parse node ID: %v", err)
		}
	}

	// Print custody columns
	columns, err := node.CustodyColumnsSlice(nodeID, cscCount, columnCount, subnetCount)
	if err != nil {
		return fmt.Errorf("failed to compute custody columns: %v", err)
	}
	type Output struct {
		PublicKey      string   `json:"public_key,omitempty"`
		NodeID         string   `json:"node_id"`
		CustodyColumns []uint64 `json:"das_custody_columns"`
	}

	output := Output{
		NodeID:         nodeID.String(),
		CustodyColumns: columns,
	}

	if fromPrivKey != "" {
		privKeyBytes, err := hex.DecodeString(fromPrivKey)
		if err != nil {
			return fmt.Errorf("failed to decode private key: %v", err)
		}
		privateKey, err := crypto.ToECDSA(privKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}
		publicKey, err := node.PublicKeyFromPrivateKey(privateKey)
		if err != nil {
			return fmt.Errorf("failed to generate public key: %v", err)
		}
		output.PublicKey = hex.EncodeToString(crypto.FromECDSAPub(publicKey))
	}

	switch outputFormat {
	case "json":
		jsonBytes, err := json.Marshal(output)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonBytes))
	case "text":
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Field", "Value"})
		table.SetBorder(true)
		table.SetRowLine(true)
		table.SetAutoWrapText(false)
		table.SetAlignment(tablewriter.ALIGN_LEFT)

		if output.PublicKey != "" {
			table.Append([]string{"Public Key", output.PublicKey})
		}
		table.Append([]string{"Node ID", output.NodeID})
		table.Append([]string{"DAS Custody Columns", formatColumns(output.CustodyColumns)})

		table.Render()
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}

	return nil
}

func formatColumns(columns []uint64) string {
	if len(columns) == 0 {
		return "[]"
	}

	parts := make([]string, 0, len(columns))
	for _, col := range columns {
		parts = append(parts, fmt.Sprintf("%d", col))
	}

	result := fmt.Sprintf("[%s]", strings.Join(parts, ", "))
	return result
}
