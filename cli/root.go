package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var root = &cobra.Command{
	Use:   "jwt command",
	Short: "jwt is a utility to generate and verify JSON Web Tokens",
}

func init() {
	root.AddCommand(generateKey)
	root.AddCommand(publicKey)
	root.AddCommand(sign)
}

// SetVersion overwrites the Version on the Root of the CLI with a subcommand
// that prints version and build information.
func SetVersion(version, revision string) {
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Display Version and Build Information",

		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "Version:  %s\nRevision: %s\n", version, revision)
		},
	})
}

// Root returns the root of the command line interface to be executed.
func Root() *cobra.Command {
	return root
}
