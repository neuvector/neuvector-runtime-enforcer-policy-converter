package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

func main() {
	app := &cli.Command{
		Name:  "converter",
		Usage: "Convert NeuVector security rules to Runtime Enforcer WorkloadPolicy",
		Commands: []*cli.Command{
			{
				Name:  "convert",
				Usage: "Convert NvSecurityRule YAML files to WorkloadPolicy YAML",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "mode",
						Aliases: []string{"m"},
						Value:   "monitor",
						Usage:   "WorkloadPolicy enforcement mode: monitor or protect",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Value:   "-",
						Usage:   "Output file path (use '-' for stdout)",
					},
				},
				Action: convertAction,
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
