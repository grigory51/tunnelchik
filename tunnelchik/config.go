package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

type config struct {
	Listen        string                 `yaml:"listen"`
	HostKey       string                 `yaml:"host_key"`
	KnownHosts    string                 `yaml:"known_hosts"`
	RecordingsDir string                 `yaml:"recordings_dir"`
	OIDC          oidcConfig             `yaml:"oidc"`
	Routes        map[string]routeConfig `yaml:"routes"`
}

type oidcConfig struct {
	Issuer   string   `yaml:"issuer"`
	ClientID string   `yaml:"client_id"`
	Scopes   []string `yaml:"scopes"`
}

type routeConfig struct {
	Address string                `yaml:"address"`
	Users   map[string]userConfig `yaml:"users"`
}

type userConfig struct {
	RequiredRoles []string `yaml:"required_roles"`
}

type targetSelection struct {
	Route         string
	Address       string
	User          string
	RequiredRoles []string
}

func loadConfig(path string) (config, error) {
	file, err := os.Open(path)
	if err != nil {
		return config{}, err
	}
	defer file.Close()

	var loaded config
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&loaded); err != nil {
		return config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return config{}, errors.New("config must contain one YAML document")
		}
		return config{}, fmt.Errorf("decode trailing YAML: %w", err)
	}
	if err := loaded.validate(); err != nil {
		return config{}, err
	}
	return loaded, nil
}

func (c config) validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	for name, path := range map[string]string{
		"host_key":       c.HostKey,
		"known_hosts":    c.KnownHosts,
		"recordings_dir": c.RecordingsDir,
	} {
		if path == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}

	issuer, err := url.Parse(c.OIDC.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || strings.HasSuffix(c.OIDC.Issuer, "/") {
		return errors.New("oidc.issuer must be an HTTPS URL without query, fragment, or trailing slash")
	}
	if c.OIDC.ClientID == "" {
		return errors.New("oidc.client_id is required")
	}
	hasOpenID := false
	for _, scope := range c.OIDC.Scopes {
		if scope == "openid" {
			hasOpenID = true
		}
		if scope == "offline_access" {
			return errors.New("oidc.scopes must not request offline_access")
		}
	}
	if !hasOpenID {
		return errors.New("oidc.scopes must include openid")
	}

	if len(c.Routes) == 0 {
		return errors.New("at least one route is required")
	}
	for routeName, route := range c.Routes {
		if !validLoginComponent(routeName) {
			return fmt.Errorf("invalid route name %q", routeName)
		}
		if _, _, err := net.SplitHostPort(route.Address); err != nil {
			return fmt.Errorf("invalid address for route %q: %w", routeName, err)
		}
		if len(route.Users) == 0 {
			return fmt.Errorf("route %q must contain at least one user", routeName)
		}
		for userName, user := range route.Users {
			if !validLoginComponent(userName) {
				return fmt.Errorf("invalid user name %q in route %q", userName, routeName)
			}
			if len(user.RequiredRoles) == 0 {
				return fmt.Errorf("user %q in route %q must require at least one role", userName, routeName)
			}
			for _, role := range user.RequiredRoles {
				if strings.TrimSpace(role) == "" {
					return fmt.Errorf("user %q in route %q contains an empty required role", userName, routeName)
				}
			}
		}
	}
	return nil
}

func (c config) resolveTarget(login string) (targetSelection, error) {
	if strings.Count(login, "+") != 1 {
		return targetSelection{}, errors.New("login must have format <route>+<target-user>")
	}
	routeName, userName, _ := strings.Cut(login, "+")
	if !validLoginComponent(routeName) || !validLoginComponent(userName) {
		return targetSelection{}, errors.New("invalid route or target user")
	}
	route, ok := c.Routes[routeName]
	if !ok {
		return targetSelection{}, errors.New("unknown route or target user")
	}
	user, ok := route.Users[userName]
	if !ok {
		return targetSelection{}, errors.New("unknown route or target user")
	}
	return targetSelection{
		Route:         routeName,
		Address:       route.Address,
		User:          userName,
		RequiredRoles: append([]string(nil), user.RequiredRoles...),
	}, nil
}

func validLoginComponent(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "+") {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}
