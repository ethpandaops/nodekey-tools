package cmd

import (
	"os"

	"github.com/ethpandaops/nodekey-tools/cmd/convert"
	"github.com/ethpandaops/nodekey-tools/cmd/generate"
	"github.com/ethpandaops/nodekey-tools/cmd/info"
	"github.com/ethpandaops/nodekey-tools/cmd/info_network"
	"github.com/ethpandaops/nodekey-tools/cmd/network"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "nodekey-tools",
	Short: "Tools for generating and managing nodekeys",
}

func Execute() {
	rootCmd.AddCommand(generate.Command)
	rootCmd.AddCommand(info.Command)
	rootCmd.AddCommand(network.Command)
	rootCmd.AddCommand(info_network.Command)
	rootCmd.AddCommand(convert.Command)

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
