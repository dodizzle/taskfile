package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dodizzle/taskfile/internal/rancher"
)

func main() {
	// Define command-line flags
	kubeconfigPath := flag.String("kubeconfig", "", "Path to kubeconfig file (default: ~/.kube/config)")
	clusterFilter := flag.String("cluster", "", "Renew token for specific cluster only")
	ttl := flag.Int("ttl", 43200, "Token TTL in minutes (default: 43200 = 30 days)")
	dryRun := flag.Bool("dry-run", false, "Preview changes without modifying files")
	debug := flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	if *dryRun {
		log.Println("DRY RUN MODE - No changes will be made")
	}

	// Create token renewer
	renewer := rancher.NewTokenRenewer(*kubeconfigPath, *dryRun, *debug)

	// Renew tokens
	results, err := renewer.RenewTokens(*clusterFilter, *ttl)
	if err != nil {
		log.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Exit with error code if any renewals failed
	if len(results.Failed) > 0 {
		os.Exit(1)
	}

	fmt.Println("\nToken renewal completed successfully!")
}
