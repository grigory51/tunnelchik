package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "/etc/tunnelchik/config.yaml", "path to the YAML config")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	loadedConfig, err := loadConfig(configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	hostKey, err := loadHostKey(loadedConfig.HostKey)
	if err != nil {
		logger.Error("failed to load host key", "error", err)
		os.Exit(1)
	}
	hostKeyCallback, err := knownhosts.New(loadedConfig.KnownHosts)
	if err != nil {
		logger.Error("failed to load known_hosts", "error", err)
		os.Exit(1)
	}
	if err := prepareRecordingsRoot(loadedConfig.RecordingsDir); err != nil {
		logger.Error("failed to prepare recordings directory", "error", err)
		os.Exit(1)
	}

	shutdownContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	authorizer, err := newAuthorizer(shutdownContext, loadedConfig.OIDC)
	if err != nil {
		logger.Error("failed to initialize OIDC", "error", err)
		os.Exit(1)
	}
	listener, err := net.Listen("tcp", loadedConfig.Listen)
	if err != nil {
		logger.Error("failed to listen", "error", err)
		os.Exit(1)
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
	if err := gateway.serve(shutdownContext, listener); err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
	logger.Info("gateway stopped")
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
