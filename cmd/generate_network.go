package cmd

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/nodekey-tools/node"
	"github.com/spf13/cobra"
)

var (
	nodeCount      uint64
	columnsPerNode uint64
	concurrency    uint64
	outputFile     string
)

var generateNetworkCmd = &cobra.Command{
	Use:   "generate-network",
	Short: "Generate a network of nodes covering all DAS columns",
	RunE:  runGenerateNetwork,
}

func init() {
	rootCmd.AddCommand(generateNetworkCmd)
	generateNetworkCmd.Flags().Uint64Var(&nodeCount, "node-count", 18, "Number of nodes to generate")
	generateNetworkCmd.Flags().Uint64Var(&columnsPerNode, "columns-per-node", 8, "Number of columns each node should custody")
	generateNetworkCmd.Flags().Uint64Var(&subnetCount, "subnet-count", 128, "Amount of data column sidecar subnets")
	generateNetworkCmd.Flags().Uint64Var(&columnCount, "column-count", 128, "Amount of columns for DAS custody columns")
	generateNetworkCmd.Flags().Uint64Var(&concurrency, "concurrency", 8, "Number of goroutines to run concurrently")
	generateNetworkCmd.Flags().StringVar(&outputFile, "output-file", "", "Path to save the network information as JSON")
}

type nodeInfo struct {
	privateKey *ecdsa.PrivateKey
	nodeID     string
	columns    []uint64
}

// Add this new type for JSON output
type NodeOutput struct {
	NodeID     string   `json:"nodeId"`
	PrivateKey string   `json:"privateKey"`
	Columns    []uint64 `json:"columns"`
}

func runGenerateNetwork(cmd *cobra.Command, args []string) error {
	// Validate that nodeCount is sufficient to cover all columns
	minRequiredNodes := columnCount / columnsPerNode
	if columnCount%columnsPerNode > 0 {
		minRequiredNodes++
	}

	if nodeCount < minRequiredNodes {
		return fmt.Errorf("node-count (%d) is too low to cover all columns; minimum required: %d nodes for %d columns with %d columns per node",
			nodeCount, minRequiredNodes, columnCount, columnsPerNode)
	}

	fmt.Printf("Generating %d nodes with %d columns per node...\n", nodeCount, columnsPerNode)

	// Track all columns covered by the network
	coveredColumns := make(map[uint64]bool)

	// Store node information
	nodes := make([]nodeInfo, 0, nodeCount)

	// Mutex for thread safety
	var mutex sync.Mutex

	// Channel for errors and completion
	errorChan := make(chan error, 1)
	doneChan := make(chan struct{})

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := uint64(0); i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mutex.Lock()
				if len(nodes) >= int(nodeCount) {
					mutex.Unlock()
					return
				}
				mutex.Unlock()

				// Add attempt counter
				attempts := uint64(0)
				foundNewNode := false
				bestNode := nodeInfo{}
				bestNewColumnsCount := 0

				for !foundNewNode {
					attempts++
					// Generate a random private key
					privateKey, err := node.GeneratePrivateKey()
					if err != nil {
						errorChan <- fmt.Errorf("failed to generate key: %v", err)
						return
					}

					// Get node ID
					nodeID, err := node.NodeIDFromPrivateKey(privateKey)
					if err != nil {
						errorChan <- fmt.Errorf("failed to generate node ID: %v", err)
						return
					}

					// Get custody columns
					columns, err := node.CustodyColumnsSlice(nodeID, columnsPerNode, columnCount, subnetCount)
					if err != nil {
						errorChan <- fmt.Errorf("failed to compute custody columns: %v", err)
						return
					}

					// Check if this node adds new columns
					mutex.Lock()
					newColumnsCount := 0
					for _, col := range columns {
						if !coveredColumns[col] {
							newColumnsCount++
						}
					}

					// Keep track of the best node we've found
					if newColumnsCount > bestNewColumnsCount {
						bestNewColumnsCount = newColumnsCount
						bestNode = nodeInfo{
							privateKey: privateKey,
							nodeID:     nodeID.String(),
							columns:    columns,
						}

						minNewColumns := columnsPerNode // Initially require $columnsPerNode new columns
						if len(coveredColumns) > int(columnCount*3/4) {
							minNewColumns = columnsPerNode * uint64(3) / uint64(4)
						}
						if len(coveredColumns) > int(columnCount*5/6) {
							minNewColumns = columnsPerNode * uint64(3) / uint64(4)
						}
						if len(coveredColumns) > int(columnCount*7/8) {
							minNewColumns = 1
						}

						// Check how many columns and nodes are missing
						missingColumns := columnCount - uint64(len(coveredColumns))
						missingNodes := nodeCount - uint64(len(nodes))
						idealNewColumns := missingColumns / missingNodes
						if idealNewColumns > minNewColumns {
							minNewColumns = idealNewColumns
						}

						if newColumnsCount >= int(minNewColumns) {
							foundNewNode = true
						}

					}
					mutex.Unlock()

				}

				mutex.Lock()
				missingColumns := (int)(columnCount) - len(coveredColumns)
				if bestNewColumnsCount >= 4 || bestNewColumnsCount == missingColumns {
					// Add the best node to the list
					nodes = append(nodes, bestNode)

					// Mark columns as covered
					for _, col := range bestNode.columns {
						coveredColumns[col] = true
					}

					// Print progress
					fmt.Printf("Generated node %d/%d, covering %d/%d columns (added %d new)\n",
						len(nodes), nodeCount, len(coveredColumns), columnCount, bestNewColumnsCount)

					// Check if we've covered all columns or reached the desired node count
					if len(coveredColumns) == int(columnCount) || len(nodes) == int(nodeCount) {
						mutex.Unlock()
						doneChan <- struct{}{}
						return
					}
				}
				mutex.Unlock()
			}
		}()
	}

	// Wait for completion or error
	select {
	case <-doneChan:
		// Success
	case err := <-errorChan:
		return err
	}

	// Print results
	fmt.Printf("\nGenerated %d nodes covering %d/%d columns\n\n", len(nodes), len(coveredColumns), columnCount)

	fmt.Println(`==============================================================================================`)
	// Create output data structure
	outputNodes := make([]NodeOutput, 0, len(nodes))

	// Print node details
	for i, node := range nodes {
		privKeyBytes := crypto.FromECDSA(node.privateKey)
		privKeyHex := hex.EncodeToString(privKeyBytes)

		fmt.Printf("Node %d:\n", i+1)
		if outputFile == "" {
			fmt.Printf("  Private Key: %s\n", privKeyHex)
		}
		fmt.Printf("  Node ID: %s\n", node.nodeID)
		fmt.Printf("  DAS Columns: %v\n\n", node.columns)

		// Add to output data
		outputNodes = append(outputNodes, NodeOutput{
			NodeID:     node.nodeID,
			PrivateKey: privKeyHex,
			Columns:    node.columns,
		})
	}

	// Print column coverage table
	printColumnCoverageTable(nodes, columnCount)

	// Print uncovered columns if any
	if len(coveredColumns) < int(columnCount) {
		uncoveredColumns := make([]uint64, 0)
		for i := uint64(0); i < columnCount; i++ {
			if !coveredColumns[i] {
				uncoveredColumns = append(uncoveredColumns, i)
			}
		}
		sort.Slice(uncoveredColumns, func(i, j int) bool {
			return uncoveredColumns[i] < uncoveredColumns[j]
		})
		fmt.Printf("Uncovered columns: %v\n", uncoveredColumns)
	}

	// Save to JSON file if output file is specified
	if outputFile != "" {
		jsonData, err := json.MarshalIndent(outputNodes, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}

		err = os.WriteFile(outputFile, jsonData, 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %v", err)
		}
		fmt.Println(`==============================================================================================`)
		fmt.Printf("Node keys have been saved to: %s\n", outputFile)
	}

	return nil
}

// Add this new function to print the column coverage table
func printColumnCoverageTable(nodes []nodeInfo, columnCount uint64) {
	// Create a map of column to nodes that cover it
	columnToNodes := make(map[uint64][]int)
	for i, node := range nodes {
		for _, col := range node.columns {
			columnToNodes[col] = append(columnToNodes[col], i+1) // +1 for 1-based node numbering
		}
	}

	fmt.Println("\nColumn Coverage Table:")
	fmt.Println("=====================")

	// Calculate the section sizes
	sectionSize := columnCount / 4
	lastSectionSize := columnCount - (3 * sectionSize) // Handle any remainder

	// Print header
	fmt.Println("+------+----------+    +------+----------+    +------+----------+    +------+----------+")
	fmt.Println("| Col  | Nodes    |    | Col  | Nodes    |    | Col  | Nodes    |    | Col  | Nodes    |")
	fmt.Println("+------+----------+    +------+----------+    +------+----------+    +------+----------+")

	// Print rows with four columns side by side
	for row := uint64(0); row < sectionSize; row++ {
		// First section
		col1 := row
		nodeList1 := columnToNodes[col1]
		sort.Ints(nodeList1)
		nodeStr1 := formatNodeList(nodeList1)

		// Second section
		col2 := row + sectionSize
		nodeList2 := columnToNodes[col2]
		sort.Ints(nodeList2)
		nodeStr2 := formatNodeList(nodeList2)

		// Third section
		col3 := row + (2 * sectionSize)
		nodeList3 := columnToNodes[col3]
		sort.Ints(nodeList3)
		nodeStr3 := formatNodeList(nodeList3)

		// Start building the output
		output := fmt.Sprintf("| %-4d | %-8s |    | %-4d | %-8s |    | %-4d | %-8s |",
			col1, nodeStr1, col2, nodeStr2, col3, nodeStr3)

		// Fourth section (may have fewer rows)
		col4 := row + (3 * sectionSize)
		if row < lastSectionSize {
			nodeList4 := columnToNodes[col4]
			sort.Ints(nodeList4)
			nodeStr4 := formatNodeList(nodeList4)
			output += fmt.Sprintf("    | %-4d | %-8s |", col4, nodeStr4)
		}

		fmt.Println(output)
	}

	// Print footer
	fmt.Println("+------+----------+    +------+----------+    +------+----------+    +------+----------+")
}

// Helper function to format the node list as a string
func formatNodeList(nodeList []int) string {
	if len(nodeList) == 0 {
		return "-"
	}

	nodeStr := ""
	for i, n := range nodeList {
		if i > 0 {
			nodeStr += ","
		}
		nodeStr += fmt.Sprintf("%d", n)
	}
	return nodeStr
}
