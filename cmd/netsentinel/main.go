package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	Version string
	log     = logrus.New()
)

var rootCmd = &cobra.Command{
	Use:   "netsentinel",
	Short: "NetSentinel - Kubernetes NetworkPolicy monitoring tool",
	Long: `NetSentinel is a tool for monitoring Kubernetes NetworkPolicy resources
and pod traffic using eBPF and flow export technologies.`,
}

func init() {
	rootCmd.AddCommand(controllerCmd)
	rootCmd.AddCommand(analyzerCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
} 