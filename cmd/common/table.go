package common

import "fmt"

type NodeInfo struct {
	NodeID  string
	Columns []uint64
}

// PrintColumnCoverageTable prints a table showing which nodes cover each column
func PrintColumnCoverageTable(nodes []NodeInfo, columnCount uint64) {
	// Create a map to track which nodes cover each column
	columnCoverage := make(map[uint64][]int, columnCount)
	for i := uint64(0); i < columnCount; i++ {
		columnCoverage[i] = make([]int, 0)
	}

	// Fill in the coverage map
	for nodeIndex, node := range nodes {
		for _, col := range node.Columns {
			columnCoverage[col] = append(columnCoverage[col], nodeIndex+1)
		}
	}

	// Print the table header
	fmt.Println("Column Coverage Table:")
	fmt.Println("Column | Nodes")
	fmt.Println("-------|------")

	// Print each column's coverage
	for i := uint64(0); i < columnCount; i++ {
		fmt.Printf("%6d | %s\n", i, formatNodeList(columnCoverage[i]))
	}
}

// formatNodeList formats a list of node indices into a comma-separated string
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
