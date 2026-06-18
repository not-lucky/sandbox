package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DefaultIdentity  string `yaml:"default_identity"`
	DefaultDNS       string `yaml:"default_dns"`
	DefaultSOCKSPort int    `yaml:"default_socks_port"`
	DefaultTimeout   int    `yaml:"default_timeout"`
	Verbose          bool   `yaml:"verbose"`
	NoSandbox        bool   `yaml:"no_sandbox"`
}

func LoadConfig() (*Config, error) {
	config := &Config{
		DefaultDNS:       "1.1.1.1",
		DefaultSOCKSPort: 10808,
	}

	configPath := ""
	if xdgHome := os.Getenv("XDG_CONFIG_HOME"); xdgHome != "" {
		configPath = filepath.Join(xdgHome, "cloakid", "config.yaml")
	} else if home, err := os.UserHomeDir(); err == nil {
		configPath = filepath.Join(home, ".cloakidrc") // Note: The spec says ~/.cloakidrc
	}

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err == nil {
			err = yaml.Unmarshal(data, config)
			if err != nil {
				return nil, err
			}
		}
	}
	return config, nil
}
