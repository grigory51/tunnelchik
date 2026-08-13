package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	rolesClaimName     = "urn:zitadel:iam:org:project:roles"
	oidcRequestTimeout = 15 * time.Second
)

type authorizer struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	httpClient   *http.Client
}

type authorizationError struct {
	Code string
	Err  error
}

func (e *authorizationError) Error() string {
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *authorizationError) Unwrap() error {
	return e.Err
}

func newAuthorizer(ctx context.Context, config oidcConfig) (*authorizer, error) {
	httpClient := &http.Client{Timeout: oidcRequestTimeout}
	discoveryContext := oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(discoveryContext, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	if endpoint.DeviceAuthURL == "" {
		return nil, errors.New("OIDC provider does not advertise a device authorization endpoint")
	}
	verifierContext := oidc.ClientContext(context.Background(), httpClient)
	return &authorizer{
		oauth2Config: oauth2.Config{
			ClientID: config.ClientID,
			Endpoint: endpoint,
			Scopes:   append([]string(nil), config.Scopes...),
		},
		verifier:   provider.VerifierContext(verifierContext, &oidc.Config{ClientID: config.ClientID}),
		httpClient: httpClient,
	}, nil
}

func (a *authorizer) authorize(
	ctx context.Context,
	userOutput io.Writer,
	requiredRoles []string,
) (sessionIdentity, error) {
	nonce, err := randomURLString(32)
	if err != nil {
		return sessionIdentity{}, &authorizationError{Code: "nonce_generation_failed", Err: err}
	}
	codeVerifier := oauth2.GenerateVerifier()
	httpContext := context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
	deviceAuthorization, err := a.oauth2Config.DeviceAuth(
		httpContext,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(codeVerifier),
	)
	if err != nil {
		return sessionIdentity{}, &authorizationError{Code: "device_authorization_failed", Err: err}
	}
	if deviceAuthorization.Expiry.IsZero() {
		return sessionIdentity{}, &authorizationError{Code: "device_authorization_invalid", Err: errors.New("missing expiry")}
	}
	var prompt string
	if deviceAuthorization.VerificationURIComplete != "" {
		prompt = fmt.Sprintf("Open %s to authorize this SSH session", deviceAuthorization.VerificationURIComplete)
	} else {
		prompt = fmt.Sprintf(
			"Open %s and enter code %s to authorize this SSH session",
			deviceAuthorization.VerificationURI,
			deviceAuthorization.UserCode,
		)
	}
	if _, err := fmt.Fprintf(userOutput, "%s. The code expires at %s.\n", prompt, deviceAuthorization.Expiry.UTC().Format(time.RFC3339)); err != nil {
		return sessionIdentity{}, &authorizationError{Code: "authorization_prompt_failed", Err: err}
	}

	pollContext, cancel := context.WithDeadline(httpContext, deviceAuthorization.Expiry)
	defer cancel()
	token, err := a.oauth2Config.DeviceAccessToken(
		pollContext,
		deviceAuthorization,
		oauth2.VerifierOption(codeVerifier),
	)
	if err != nil {
		return sessionIdentity{}, &authorizationError{Code: "device_authorization_denied", Err: err}
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return sessionIdentity{}, &authorizationError{Code: "id_token_missing", Err: errors.New("token response has no ID token")}
	}
	verifiedToken, err := a.verifier.Verify(pollContext, rawIDToken)
	if err != nil {
		return sessionIdentity{}, &authorizationError{Code: "id_token_invalid", Err: err}
	}
	var claims struct {
		Subject string                     `json:"sub"`
		Name    string                     `json:"name"`
		Email   string                     `json:"email"`
		Nonce   string                     `json:"nonce"`
		Roles   map[string]json.RawMessage `json:"urn:zitadel:iam:org:project:roles"`
	}
	if err := verifiedToken.Claims(&claims); err != nil {
		return sessionIdentity{}, &authorizationError{Code: "id_token_claims_invalid", Err: err}
	}
	if claims.Subject == "" {
		return sessionIdentity{}, &authorizationError{Code: "subject_missing", Err: errors.New("ID token has no subject")}
	}
	if claims.Nonce != nonce {
		return sessionIdentity{}, &authorizationError{Code: "nonce_invalid", Err: errors.New("ID token nonce does not match the device flow")}
	}
	for _, role := range requiredRoles {
		if _, ok := claims.Roles[role]; !ok {
			return sessionIdentity{}, &authorizationError{Code: "required_role_missing", Err: fmt.Errorf("required role %q is absent", role)}
		}
	}
	return sessionIdentity{Subject: claims.Subject, Name: claims.Name, Email: claims.Email}, nil
}

func randomURLString(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
