package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestGatewayExecUsesForwardedAgentAfterAuthorization(t *testing.T) {
	_, targetHostKey := newTestSigner(t)
	agentPrivateKey, agentKey := newTestSigner(t)
	_, gatewayHostKey := newTestSigner(t)
	_, inboundKey := newTestSigner(t)

	targetConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() != "ozhegov" || !bytes.Equal(key.Marshal(), agentKey.PublicKey().Marshal()) {
				return nil, fmt.Errorf("unauthorized key")
			}
			return nil, nil
		},
	}
	targetConfig.AddHostKey(targetHostKey)
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	targetResult := make(chan error, 1)
	go func() { targetResult <- serveTestTarget(targetListener, targetConfig) }()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oidcServer := newTestOIDCServer(t, privateKey, []string{"tunnelchik:user"}, false)
	defer oidcServer.Close()
	authorizer, err := newAuthorizer(context.Background(), oidcConfig{
		Issuer: oidcServer.URL, ClientID: "tunnelchik", Scopes: []string{"openid", rolesClaimName},
	})
	if err != nil {
		t.Fatal(err)
	}

	recordingsDirectory := t.TempDir()
	gatewayListener, client := startTestGateway(
		t,
		targetListener.Addr().String(),
		targetHostKey.PublicKey(),
		gatewayHostKey,
		inboundKey,
		agentPrivateKey,
		authorizer,
		recordingsDirectory,
		[]string{"tunnelchik:user"},
	)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.RequestAgentForwarding(session); err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("id")
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "uid=1000(ozhegov)\n" {
		t.Fatalf("unexpected output: %q", output)
	}
	session.Close()
	client.Close()
	gatewayListener.cancel()
	if err := <-gatewayListener.result; err != nil {
		t.Fatal(err)
	}
	if err := <-targetResult; err != nil {
		t.Fatal(err)
	}

	metadata := readSingleRecordingMetadata(t, recordingsDirectory)
	if metadata.Authorization != "allowed" || metadata.Identity == nil || metadata.Identity.Subject != "user-1" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if len(metadata.AgentKeyFingerprints) != 1 || metadata.ExitStatus == nil || *metadata.ExitStatus != 0 {
		t.Fatalf("incomplete metadata: %+v", metadata)
	}
}

func TestGatewayDeniesBeforeOpeningTarget(t *testing.T) {
	_, targetHostKey := newTestSigner(t)
	agentPrivateKey, _ := newTestSigner(t)
	_, gatewayHostKey := newTestSigner(t)
	_, inboundKey := newTestSigner(t)
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oidcServer := newTestOIDCServer(t, privateKey, []string{"other"}, false)
	defer oidcServer.Close()
	authorizer, err := newAuthorizer(context.Background(), oidcConfig{
		Issuer: oidcServer.URL, ClientID: "tunnelchik", Scopes: []string{"openid", rolesClaimName},
	})
	if err != nil {
		t.Fatal(err)
	}

	recordingsDirectory := t.TempDir()
	gatewayListener, client := startTestGateway(
		t,
		targetListener.Addr().String(),
		targetHostKey.PublicKey(),
		gatewayHostKey,
		inboundKey,
		agentPrivateKey,
		authorizer,
		recordingsDirectory,
		[]string{"tunnelchik:user"},
	)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.RequestAgentForwarding(session); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Output("id"); err == nil {
		t.Fatal("expected authorization denial")
	}
	session.Close()
	client.Close()
	gatewayListener.cancel()
	if err := <-gatewayListener.result; err != nil {
		t.Fatal(err)
	}

	tcpListener := targetListener.(*net.TCPListener)
	if err := tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, err := tcpListener.Accept()
	if err == nil {
		connection.Close()
		t.Fatal("gateway opened target connection before authorization")
	}
	if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("unexpected target accept error: %v", err)
	}
	metadata := readSingleRecordingMetadata(t, recordingsDirectory)
	if metadata.Authorization != "denied" || metadata.FailureCode != "required_role_missing" {
		t.Fatalf("unexpected denial metadata: %+v", metadata)
	}
}

type testGatewayListener struct {
	cancel context.CancelFunc
	result <-chan error
}

func startTestGateway(
	t *testing.T,
	targetAddress string,
	targetHostKey ssh.PublicKey,
	gatewayHostKey ssh.Signer,
	inboundKey ssh.Signer,
	agentPrivateKey ed25519.PrivateKey,
	authorizer *authorizer,
	recordingsDirectory string,
	requiredRoles []string,
) (testGatewayListener, *ssh.Client) {
	t.Helper()
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	knownHostsLine := knownhosts.Line([]string{knownhosts.Normalize(targetAddress)}, targetHostKey)
	if err := os.WriteFile(knownHostsPath, []byte(knownHostsLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	testGateway := &gateway{
		config: config{
			RecordingsDir: recordingsDirectory,
			Routes: map[string]routeConfig{"bots": {
				Address: targetAddress,
				Users:   map[string]userConfig{"ozhegov": {RequiredRoles: requiredRoles}},
			}},
		},
		hostKey: gatewayHostKey, hostKeyCallback: hostKeyCallback, authorizer: authorizer,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	result := make(chan error, 1)
	go func() { result <- testGateway.serve(ctx, listener) }()

	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
		User: "bots+ozhegov", Auth: []ssh.AuthMethod{ssh.PublicKeys(inboundKey)},
		HostKeyCallback: ssh.FixedHostKey(gatewayHostKey.PublicKey()),
	})
	if err != nil {
		cancel()
		listener.Close()
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: agentPrivateKey}); err != nil {
		t.Fatal(err)
	}
	if err := agent.ForwardToAgent(client, keyring); err != nil {
		t.Fatal(err)
	}
	return testGatewayListener{cancel: cancel, result: result}, client
}

func readSingleRecordingMetadata(t *testing.T, root string) sessionMetadata {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "*", "*", "*", "*", "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected one recording, got %d", len(paths))
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var metadata sessionMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func newTestSigner(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, signer
}

func serveTestTarget(listener net.Listener, config *ssh.ServerConfig) error {
	networkConnection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer networkConnection.Close()
	connection, channels, requests, err := ssh.NewServerConn(networkConnection, config)
	if err != nil {
		return err
	}
	defer connection.Close()
	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			if err := newChannel.Reject(ssh.Prohibited, "session required"); err != nil {
				return err
			}
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			return err
		}
		defer channel.Close()
		for request := range channelRequests {
			if request.Type != "exec" {
				if err := request.Reply(false, nil); err != nil {
					return err
				}
				continue
			}
			var payload execRequestPayload
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
				return err
			}
			if strings.TrimSpace(payload.Command) != "id" {
				return fmt.Errorf("unexpected command: %q", payload.Command)
			}
			if err := request.Reply(true, nil); err != nil {
				return err
			}
			if _, err := channel.Write([]byte("uid=1000(ozhegov)\n")); err != nil {
				return err
			}
			if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusPayload{Status: 0})); err != nil {
				return err
			}
			return channel.Close()
		}
	}
	return nil
}
