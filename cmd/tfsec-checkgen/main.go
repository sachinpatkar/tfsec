package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func init() {
	rootCmd.Flags().Bool("validate", false, "Validate the provided check file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tfsec-checkgen [file]",
	Short: "tfsec-checkgen is a tfsec tool for generating and validating custom check files.",
	Long: `tfsec is a simple tool for generating and validating custom checks file.
Custom checks are defined as json and stored in the .tfsec directory of the folder being checked.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Print("tfsec-checkgen requires a single ")
		}

		validate := cmd.Flags().GetBool("validate")

		if validate {
			custom.Validate(args[0])
		}
	},
}
