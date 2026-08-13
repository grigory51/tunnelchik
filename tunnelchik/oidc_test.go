package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthorizerVerifiesNonceAndRoles(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name         string
		roles        []string
		wrongNonce   bool
		expectedCode string
	}{
		{name: "allowed", roles: []string{"tunnelchik:user"}},
		{name: "missing role", roles: []string{"other"}, expectedCode: "required_role_missing"},
		{name: "wrong nonce", roles: []string{"tunnelchik:user"}, wrongNonce: true, expectedCode: "nonce_invalid"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := newTestOIDCServer(t, privateKey, testCase.roles, testCase.wrongNonce)
			defer server.Close()
			authorizer, err := newAuthorizer(context.Background(), oidcConfig{
				Issuer:   server.URL,
				ClientID: "tunnelchik",
				Scopes:   []string{"openid", "profile", "email", rolesClaimName},
			})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			identity, err := authorizer.authorize(context.Background(), &output, []string{"tunnelchik:user"})
			if testCase.expectedCode == "" {
				if err != nil {
					t.Fatal(err)
				}
				if identity.Subject != "user-1" || !strings.Contains(output.String(), "/verify") {
					t.Fatalf("unexpected authorization result: %+v %q", identity, output.String())
				}
				return
			}
			var authorizationFailure *authorizationError
			if err == nil || !errors.As(err, &authorizationFailure) || authorizationFailure.Code != testCase.expectedCode {
				t.Fatalf("expected %s, got %v", testCase.expectedCode, err)
			}
		})
	}
}

func newTestOIDCServer(t *testing.T, privateKey *rsa.PrivateKey, roles []string, wrongNonce bool) *httptest.Server {
	t.Helper()
	var mutex sync.Mutex
	nonce := ""
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(t, writer, map[string]any{
				"issuer":                                server.URL,
				"authorization_endpoint":                server.URL + "/authorize",
				"device_authorization_endpoint":         server.URL + "/device",
				"token_endpoint":                        server.URL + "/token",
				"jwks_uri":                              server.URL + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/device":
			if err := request.ParseForm(); err != nil {
				t.Error(err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			mutex.Lock()
			nonce = request.Form.Get("nonce")
			mutex.Unlock()
			if request.Form.Get("code_challenge") == "" {
				t.Error("missing PKCE challenge")
			}
			writeTestJSON(t, writer, map[string]any{
				"device_code":               "device-code",
				"user_code":                 "ABCD-EFGH",
				"verification_uri":          server.URL + "/verify",
				"verification_uri_complete": server.URL + "/verify?code=ABCD-EFGH",
				"expires_in":                60,
				"interval":                  1,
			})
		case "/token":
			if err := request.ParseForm(); err != nil {
				t.Error(err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			mutex.Lock()
			tokenNonce := nonce
			mutex.Unlock()
			if wrongNonce {
				tokenNonce = "wrong"
			}
			roleClaim := make(map[string]any, len(roles))
			for _, role := range roles {
				roleClaim[role] = map[string]string{"org-1": "example.com"}
			}
			idToken := signTestJWT(t, privateKey, map[string]any{
				"iss":          server.URL,
				"sub":          "user-1",
				"aud":          "tunnelchik",
				"exp":          time.Now().Add(time.Minute).Unix(),
				"iat":          time.Now().Unix(),
				"nonce":        tokenNonce,
				"name":         "Test User",
				"email":        "user@example.com",
				rolesClaimName: roleClaim,
			})
			writeTestJSON(t, writer, map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"expires_in":   60,
				"id_token":     idToken,
			})
		case "/keys":
			exponent := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
			writeTestJSON(t, writer, map[string]any{"keys": []any{map[string]any{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(exponent),
			}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

func signTestJWT(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeTestJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Error(err)
	}
}
