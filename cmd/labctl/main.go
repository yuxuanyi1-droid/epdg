// Command labctl manages the containerised ePDG lab.
//
//	labctl render   turn deploy/lab.yaml into deploy/.env and deploy/runtime
//	labctl serve    serve the configuration UI and its API
//
// deploy/lab.yaml is the single source of truth for addresses, the PLMN, the
// subscriber credentials and the ePDG/EPC/eNB parameters. The UI edits that
// file through the API; `render` is what makes the containers pick the changes
// up.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"epdg/internal/lab"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "render":
		if err := runRender(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "labctl render:", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "labctl serve:", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "labctl: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `labctl manages the containerised ePDG lab.

Usage:
  labctl render [-lab deploy/lab.yaml] [-deploy deploy]
  labctl serve  [-lab deploy/lab.yaml] [-deploy deploy] [-listen 127.0.0.1:8088]

Commands:
  render   Regenerate deploy/.env and deploy/runtime from the lab definition.
  serve    Serve the configuration UI and its REST API.

`)
}

// repoRootFromDeploy walks up from the deploy directory to the repository root,
// which is where configs/ lives.
func repoRootFromDeploy(deployDir string) string {
	abs, err := filepath.Abs(deployDir)
	if err != nil {
		return filepath.Dir(deployDir)
	}
	return filepath.Dir(abs)
}

func runRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	labPath := fs.String("lab", filepath.Join("deploy", "lab.yaml"), "path to the lab definition")
	deployDir := fs.String("deploy", "deploy", "deploy directory to write into")
	quiet := fs.Bool("quiet", false, "only report errors")
	if err := fs.Parse(args); err != nil {
		return err
	}

	def, err := lab.Load(*labPath)
	if err != nil {
		return err
	}
	renderer := lab.NewRenderer(repoRootFromDeploy(*deployDir), *deployDir, def)
	result, err := renderer.Render()
	if err != nil {
		return err
	}
	if !*quiet {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		logger.Info("rendered the lab",
			"env", result.EnvFile,
			"files", len(result.Files),
			"network", def.Network.Name)
		for _, f := range result.Files {
			fmt.Println("  ", f)
		}
	}
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	labPath := fs.String("lab", filepath.Join("deploy", "lab.yaml"), "path to the lab definition")
	deployDir := fs.String("deploy", "deploy", "deploy directory to render into")
	listen := fs.String("listen", "127.0.0.1:8088", "address for the configuration UI")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	return lab.Serve(lab.ServerOptions{
		LabPath:   *labPath,
		DeployDir: *deployDir,
		RepoRoot:  repoRootFromDeploy(*deployDir),
		Listen:    *listen,
		Logger:    logger,
	})
}
