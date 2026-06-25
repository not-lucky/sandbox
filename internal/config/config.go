package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DefaultIdentity  string              `yaml:"default_identity"`
	DefaultDNS       string              `yaml:"default_dns"`
	DefaultSOCKSPort int                 `yaml:"default_socks_port"`
	DefaultTimeout   int                 `yaml:"default_timeout"`
	Verbose          bool                `yaml:"verbose"`
	NoSandbox        bool                `yaml:"no_sandbox"`
	NoProxy          bool                `yaml:"no_proxy"`
	Aliases          map[string][]string `yaml:"aliases,omitempty"`
}

func GetConfigPath() (string, error) {
	if xdgHome := os.Getenv("XDG_CONFIG_HOME"); xdgHome != "" {
		return filepath.Join(xdgHome, "cloakid", "config.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cloakidrc"), nil
}

func LoadConfig() (*Config, error) {
	config := &Config{
		DefaultDNS:       "1.1.1.1",
		DefaultSOCKSPort: 10808,
	}

	configPath, err := GetConfigPath()
	if err == nil && configPath != "" {
		data, err := os.ReadFile(configPath)
		if err == nil {
			err = yaml.Unmarshal(data, config)
			if err != nil {
				return nil, err
			}
		}
	}
	if config.Aliases == nil {
		config.Aliases = make(map[string][]string)
	}
	return config, nil
}

func SaveConfig(cfg *Config) error {
	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0600)
}
