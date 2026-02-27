package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	lh "github.com/RantaSec/golinhound"
)

func main() {
	// define subcommands
	collectCmd := flag.NewFlagSet("collect", flag.ExitOnError)
	collectDuration := collectCmd.Int("wait-for-keys", 0, "Time in minutes to wait for new forwarded SSH keys (0 = no wait)")
	collectVerbose := collectCmd.Bool("verbose", false, "Enable verbose output")
	mergeCmd := flag.NewFlagSet("merge", flag.ExitOnError)
	mergeVerbose := mergeCmd.Bool("verbose", false, "Enable verbose output")

	// make sure a subcommand has been specified
	if len(os.Args) < 2 {
		printCommandUsage()
		os.Exit(1)
	}

	// switch between subcommands
	switch os.Args[1] {
	case "collect":
		collectCmd.Parse(os.Args[2:])
		lh.Verbose = *collectVerbose
		result := lh.NewLinhoundCollector().CollectArtifactsOpenGraph(*collectDuration)
		fmt.Println(result)
	case "merge":
		mergeCmd.Parse(os.Args[2:])
		lh.Verbose = *mergeVerbose
		result := lh.MergeOpenGraphJSONs()
		fmt.Println(result)
	default:
		printCommandUsage()
		os.Exit(1)
	}
}

// printCommandUsage prints the subcommand usage to stderr
func printCommandUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s <command> [options]

Commands:
 collect    collect attack path data from current computer (requires root privileges)
 merge      read stream of OpenGraph JSON objects from stdin and merge them into one JSON

Use "%s <command> -h" for more information about a command.

Copyright (c) 2026 Lukas Klein
`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}
