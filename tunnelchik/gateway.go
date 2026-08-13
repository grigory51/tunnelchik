package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	agentForwardingRequest = "auth-agent-req@openssh.com"
	forwardedAgentChannel  = "auth-agent@openssh.com"
	targetDialTimeout      = 10 * time.Second
)

type gateway struct {
	config          config
	hostKey         ssh.Signer
	hostKeyCallback ssh.HostKeyCallback
	authorizer      *authorizer
	logger          *slog.Logger
}

type ptyRequestPayload struct {
	Term                      string
	Columns, Rows             uint32
	WidthPixels, HeightPixels uint32
	Modes                     string
}

type windowChangePayload struct {
	Columns, Rows             uint32
	WidthPixels, HeightPixels uint32
}

type execRequestPayload struct {
	Command string
}

type exitStatusPayload struct {
	Status uint32
}

type exitSignalPayload struct {
	SignalName   string
	CoreDumped   bool
	ErrorMessage string
	LanguageTag  string
}

func (g *gateway) serve(ctx context.Context, listener net.Listener) error {
	stopClosingListener := make(chan struct{})
	defer close(stopClosingListener)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-stopClosingListener:
		}
	}()

	var connections sync.WaitGroup
	for {
		connection, err := listener.Accept()
		if err != nil {
			connections.Wait()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		connectionContext, cancelConnection := context.WithCancel(ctx)
		connectionDone := make(chan struct{})
		go func() {
			select {
			case <-connectionContext.Done():
				connection.Close()
			case <-connectionDone:
			}
		}()
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer close(connectionDone)
			defer cancelConnection()
			if err := g.handleConnection(connectionContext, connection); err != nil {
				g.logger.Warn("SSH connection closed with error", "source", connection.RemoteAddr(), "error", err)
			}
		}()
	}
}

func (g *gateway) handleConnection(parentContext context.Context, networkConnection net.Conn) (result error) {
	defer networkConnection.Close()

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, err := g.config.resolveTarget(metadata.User()); err != nil {
				return nil, err
			}
			return &ssh.Permissions{Extensions: map[string]string{
				"key-fingerprint": ssh.FingerprintSHA256(key),
			}}, nil
		},
	}
	serverConfig.AddHostKey(g.hostKey)
	serverConnection, channels, requests, err := ssh.NewServerConn(networkConnection, serverConfig)
	if err != nil {
		return fmt.Errorf("complete inbound handshake: %w", err)
	}
	defer serverConnection.Close()
	go ssh.DiscardRequests(requests)

	target, err := g.config.resolveTarget(serverConnection.User())
	if err != nil {
		return fmt.Errorf("resolve authenticated target: %w", err)
	}
	recorder, err := newSessionRecorder(g.config.RecordingsDir, sessionMetadata{
		SourceAddress:         serverConnection.RemoteAddr().String(),
		Route:                 target.Route,
		TargetAddress:         target.Address,
		TargetUser:            target.User,
		InboundKeyFingerprint: serverConnection.Permissions.Extensions["key-fingerprint"],
	})
	if err != nil {
		return fmt.Errorf("create session recorder: %w", err)
	}
	defer func() {
		result = errors.Join(result, recorder.Close())
	}()

	connectionContext, cancelConnection := context.WithCancel(parentContext)
	defer cancelConnection()
	go func() {
		serverConnection.Wait()
		cancelConnection()
	}()
	g.logger.Info("SSH connection authenticated",
		"session_id", recorder.metadata.SessionID,
		"source", serverConnection.RemoteAddr(),
		"user", serverConnection.User(),
		"key_fingerprint", serverConnection.Permissions.Extensions["key-fingerprint"],
	)

	for {
		select {
		case <-connectionContext.Done():
			return connectionContext.Err()
		case newChannel, ok := <-channels:
			if !ok {
				return nil
			}
			if newChannel.ChannelType() != "session" {
				if err := newChannel.Reject(ssh.Prohibited, "only one session channel is allowed"); err != nil {
					return fmt.Errorf("reject inbound channel: %w", err)
				}
				continue
			}
			inboundChannel, inboundRequests, err := newChannel.Accept()
			if err != nil {
				return fmt.Errorf("accept inbound session: %w", err)
			}
			go func() {
				for extraChannel := range channels {
					if err := extraChannel.Reject(ssh.Prohibited, "only one session channel is allowed"); err != nil {
						g.logger.Debug("failed to reject extra inbound channel", "error", err)
					}
				}
			}()
			return g.handleSession(connectionContext, serverConnection, inboundChannel, inboundRequests, target, recorder)
		}
	}
}

func (g *gateway) handleSession(
	ctx context.Context,
	inboundConnection *ssh.ServerConn,
	inboundChannel ssh.Channel,
	inboundRequests <-chan *ssh.Request,
	target targetSelection,
	recorder *sessionRecorder,
) error {
	defer inboundChannel.Close()
	var agentChannel ssh.Channel
	var forwardedAgent agent.Agent
	var targetClient *ssh.Client
	var targetChannel ssh.Channel
	var proxyResult <-chan error
	defer func() {
		if targetChannel != nil {
			targetChannel.Close()
		}
		if targetClient != nil {
			targetClient.Close()
		}
		if agentChannel != nil {
			agentChannel.Close()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if targetChannel != nil {
				targetChannel.Close()
				inboundChannel.Close()
				if err := <-proxyResult; err != nil {
					return errors.Join(ctx.Err(), err)
				}
			}
			return ctx.Err()
		case err := <-proxyResult:
			if err != nil {
				recorder.fail("session_proxy_failed")
				return err
			}
			return nil
		case request, ok := <-inboundRequests:
			if !ok {
				if targetChannel != nil {
					targetChannel.Close()
					inboundChannel.Close()
					return <-proxyResult
				}
				return nil
			}
			switch request.Type {
			case agentForwardingRequest:
				if forwardedAgent != nil {
					if err := request.Reply(false, nil); err != nil {
						return fmt.Errorf("reject duplicate agent forwarding: %w", err)
					}
					continue
				}
				var agentRequests <-chan *ssh.Request
				var err error
				agentChannel, agentRequests, err = inboundConnection.OpenChannel(forwardedAgentChannel, nil)
				if err != nil {
					return errors.Join(fmt.Errorf("open forwarded agent channel: %w", err), replyRequest(request, false))
				}
				go ssh.DiscardRequests(agentRequests)
				forwardedAgent = agent.NewClient(agentChannel)
				if err := request.Reply(true, nil); err != nil {
					return fmt.Errorf("accept agent forwarding: %w", err)
				}

			case "pty-req", "shell", "exec":
				if targetChannel == nil {
					if forwardedAgent == nil {
						if err := request.Reply(false, nil); err != nil {
							return fmt.Errorf("reject session without forwarded agent: %w", err)
						}
						recorder.fail("agent_forwarding_required")
						if _, err := fmt.Fprintln(inboundChannel.Stderr(), "tunnelchik: agent forwarding is required"); err != nil {
							return fmt.Errorf("write agent forwarding error: %w", err)
						}
						return errors.New("agent forwarding is required")
					}
					keys, err := forwardedAgent.List()
					if err != nil || len(keys) == 0 {
						if replyErr := request.Reply(false, nil); replyErr != nil {
							return errors.Join(fmt.Errorf("list forwarded agent keys: %w", err), replyErr)
						}
						recorder.fail("agent_keys_unavailable")
						if _, writeErr := fmt.Fprintln(inboundChannel.Stderr(), "tunnelchik: forwarded agent has no usable keys"); writeErr != nil {
							return errors.Join(err, writeErr)
						}
						if err != nil {
							return fmt.Errorf("list forwarded agent keys: %w", err)
						}
						return errors.New("forwarded agent has no keys")
					}
					fingerprints := make([]string, 0, len(keys))
					for _, key := range keys {
						fingerprints = append(fingerprints, ssh.FingerprintSHA256(key))
					}
					if err := recorder.setAgentFingerprints(fingerprints); err != nil {
						return errors.Join(fmt.Errorf("record agent fingerprints: %w", err), replyRequest(request, false))
					}

					identity, err := g.authorizer.authorize(ctx, inboundChannel.Stderr(), target.RequiredRoles)
					if err != nil {
						if replyErr := request.Reply(false, nil); replyErr != nil {
							return errors.Join(fmt.Errorf("authorize session: %w", err), replyErr)
						}
						failureCode := "authorization_failed"
						var authorizationFailure *authorizationError
						if errors.As(err, &authorizationFailure) {
							failureCode = authorizationFailure.Code
						}
						if metadataErr := recorder.setDenied(failureCode); metadataErr != nil {
							return errors.Join(fmt.Errorf("authorize session: %w", err), metadataErr)
						}
						if _, writeErr := fmt.Fprintln(inboundChannel.Stderr(), "tunnelchik: authorization failed"); writeErr != nil {
							return errors.Join(fmt.Errorf("authorize session: %w", err), writeErr)
						}
						return fmt.Errorf("authorize session: %w", err)
					}
					if err := recorder.setAuthorized(identity); err != nil {
						return errors.Join(fmt.Errorf("record authorized identity: %w", err), replyRequest(request, false))
					}

					var targetRequests <-chan *ssh.Request
					targetClient, targetChannel, targetRequests, err = g.openTargetSession(target, forwardedAgent)
					if err != nil {
						if replyErr := request.Reply(false, nil); replyErr != nil {
							return errors.Join(fmt.Errorf("open target session: %w", err), replyErr)
						}
						recorder.fail("target_connection_failed")
						if _, writeErr := fmt.Fprintln(inboundChannel.Stderr(), "tunnelchik: target connection failed"); writeErr != nil {
							return errors.Join(fmt.Errorf("open target session: %w", err), writeErr)
						}
						return fmt.Errorf("open target session: %w", err)
					}
					proxyResult = g.proxySession(inboundChannel, targetChannel, targetRequests, recorder)
				}

				if err := recordSessionRequest(recorder, request); err != nil {
					recorder.fail("recording_failed")
					return errors.Join(fmt.Errorf("record %s request: %w", request.Type, err), replyRequest(request, false))
				}
				accepted, err := targetChannel.SendRequest(request.Type, request.WantReply, request.Payload)
				if err != nil {
					return fmt.Errorf("forward %s request: %w", request.Type, err)
				}
				if err := request.Reply(accepted, nil); err != nil {
					return fmt.Errorf("reply to %s request: %w", request.Type, err)
				}

			case "window-change", "signal":
				if targetChannel == nil {
					if err := request.Reply(false, nil); err != nil {
						return fmt.Errorf("reject premature %s request: %w", request.Type, err)
					}
					continue
				}
				if err := recordSessionRequest(recorder, request); err != nil {
					recorder.fail("recording_failed")
					return fmt.Errorf("record %s request: %w", request.Type, err)
				}
				accepted, err := targetChannel.SendRequest(request.Type, request.WantReply, request.Payload)
				if err != nil {
					return fmt.Errorf("forward %s request: %w", request.Type, err)
				}
				if err := request.Reply(accepted, nil); err != nil {
					return fmt.Errorf("reply to %s request: %w", request.Type, err)
				}

			default:
				if err := request.Reply(false, nil); err != nil {
					return fmt.Errorf("reject %s request: %w", request.Type, err)
				}
			}
		}
	}
}

func replyRequest(request *ssh.Request, accepted bool) error {
	if err := request.Reply(accepted, nil); err != nil {
		return fmt.Errorf("reply to %s request: %w", request.Type, err)
	}
	return nil
}

func recordSessionRequest(recorder *sessionRecorder, request *ssh.Request) error {
	switch request.Type {
	case "exec":
		var payload execRequestPayload
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			return err
		}
		return recorder.recordExec(payload.Command)
	case "pty-req":
		var payload ptyRequestPayload
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			return err
		}
		return recorder.recordResize(payload.Columns, payload.Rows)
	case "window-change":
		var payload windowChangePayload
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			return err
		}
		return recorder.recordResize(payload.Columns, payload.Rows)
	default:
		return nil
	}
}

func (g *gateway) openTargetSession(
	target targetSelection,
	forwardedAgent agent.Agent,
) (*ssh.Client, ssh.Channel, <-chan *ssh.Request, error) {
	clientConfig := &ssh.ClientConfig{
		User:            target.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(forwardedAgent.Signers)},
		HostKeyCallback: g.hostKeyCallback,
		Timeout:         targetDialTimeout,
	}
	targetClient, err := ssh.Dial("tcp", target.Address, clientConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	targetChannel, targetRequests, err := targetClient.OpenChannel("session", nil)
	if err != nil {
		targetClient.Close()
		return nil, nil, nil, err
	}
	return targetClient, targetChannel, targetRequests, nil
}

func (g *gateway) proxySession(
	inboundChannel ssh.Channel,
	targetChannel ssh.Channel,
	targetRequests <-chan *ssh.Request,
	recorder *sessionRecorder,
) <-chan error {
	result := make(chan error, 1)
	errorsFound := make(chan error, 1)
	var errorOnce sync.Once
	reportError := func(err error) {
		errorOnce.Do(func() { errorsFound <- err })
	}

	var allStreams sync.WaitGroup
	allStreams.Add(4)
	var targetOutput sync.WaitGroup
	targetOutput.Add(3)
	go func() {
		defer targetOutput.Done()
		defer allStreams.Done()
		if _, err := io.Copy(io.MultiWriter(recorder, inboundChannel), targetChannel); err != nil {
			reportError(fmt.Errorf("proxy target stdout: %w", err))
		}
	}()
	go func() {
		defer targetOutput.Done()
		defer allStreams.Done()
		if _, err := io.Copy(io.MultiWriter(recorder, inboundChannel.Stderr()), targetChannel.Stderr()); err != nil {
			reportError(fmt.Errorf("proxy target stderr: %w", err))
		}
	}()
	go func() {
		defer targetOutput.Done()
		defer allStreams.Done()
		for request := range targetRequests {
			switch request.Type {
			case "exit-status":
				var payload exitStatusPayload
				if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
					reportError(fmt.Errorf("decode target exit status: %w", err))
					return
				}
				recorder.setExitStatus(payload.Status)
			case "exit-signal":
				var payload exitSignalPayload
				if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
					reportError(fmt.Errorf("decode target exit signal: %w", err))
					return
				}
				recorder.setExitSignal(payload.SignalName)
			default:
				if err := request.Reply(false, nil); err != nil {
					reportError(fmt.Errorf("reject target request %s: %w", request.Type, err))
					return
				}
				continue
			}
			accepted, err := inboundChannel.SendRequest(request.Type, request.WantReply, request.Payload)
			if err != nil {
				reportError(fmt.Errorf("forward target %s request: %w", request.Type, err))
				return
			}
			if err := request.Reply(accepted, nil); err != nil {
				reportError(fmt.Errorf("reply to target %s request: %w", request.Type, err))
				return
			}
		}
	}()
	go func() {
		defer allStreams.Done()
		if _, err := io.Copy(io.MultiWriter(recorder.inputWriter(), targetChannel), inboundChannel); err != nil {
			reportError(fmt.Errorf("proxy client input: %w", err))
			return
		}
		if err := targetChannel.CloseWrite(); err != nil {
			reportError(fmt.Errorf("close target input: %w", err))
		}
	}()
	go func() {
		targetDone := make(chan struct{})
		go func() {
			targetOutput.Wait()
			close(targetDone)
		}()

		var proxyError error
		select {
		case proxyError = <-errorsFound:
		case <-targetDone:
			if err := inboundChannel.CloseWrite(); err != nil {
				g.logger.Debug("failed to close inbound output", "error", err)
			}
		}
		targetChannel.Close()
		inboundChannel.Close()
		allStreams.Wait()
		result <- proxyError
		close(result)
	}()
	return result
}
