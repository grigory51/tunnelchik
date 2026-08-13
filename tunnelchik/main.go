package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var buildVersion = "dev"

func main() {
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("command failed", "error", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var configPath string
	command := &cobra.Command{
		Use:           "tunnelchik",
		Short:         "SSH gateway with ZITADEL authorization and session recording",
		Version:       buildVersion,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(command *cobra.Command, _ []string) error {
			return runGateway(command.Context(), configPath)
		},
	}
	command.Flags().StringVar(&configPath, "config", "/etc/tunnelchik/config.yaml", "path to the YAML config")
	return command
}

func runGateway(ctx context.Context, configPath string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	loadedConfig, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	hostKey, err := loadHostKey(loadedConfig.HostKey)
	if err != nil {
		return fmt.Errorf("load host key: %w", err)
	}
	hostKeyCallback, err := knownhosts.New(loadedConfig.KnownHosts)
	if err != nil {
		return fmt.Errorf("load known_hosts: %w", err)
	}
	if err := prepareRecordingsRoot(loadedConfig.RecordingsDir); err != nil {
		return fmt.Errorf("prepare recordings directory: %w", err)
	}

	authorizer, err := newAuthorizer(ctx, loadedConfig.OIDC)
	if err != nil {
		return fmt.Errorf("initialize OIDC: %w", err)
	}
	listener, err := net.Listen("tcp", loadedConfig.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	gateway := &gateway{
		config:          loadedConfig,
		hostKey:         hostKey,
		hostKeyCallback: hostKeyCallback,
		authorizer:      authorizer,
		logger:          logger,
	}
	logger.Info("gateway started", "listen", listener.Addr())
	if err := gateway.serve(ctx, listener); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("serve gateway: %w", err)
	}
	logger.Info("gateway stopped")
	return nil
}

func loadHostKey(path string) (ssh.Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("host key %q must have mode 0600, got %04o", path, info.Mode().Perm())
	}
	privateKey, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privateKey)
}

func prepareRecordingsRoot(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("recordings path %q is not a directory", path)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("recordings directory %q must have mode 0700, got %04o", path, info.Mode().Perm())
	}
	return nil
}
