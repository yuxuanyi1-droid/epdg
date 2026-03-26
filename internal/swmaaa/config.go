package swmaaa

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen         string        `yaml:"listen"`
	OriginHost     string        `yaml:"origin_host"`
	OriginRealm    string        `yaml:"origin_realm"`
	ProductName    string        `yaml:"product_name"`
	AllowUnknown   bool          `yaml:"allow_unknown_imsi"`
	AllowedIMSIs   []string      `yaml:"allowed_imsis"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	SessionTimeout time.Duration `yaml:"session_timeout"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml %s: %w", path, err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.19:3869"
	}
	if cfg.OriginHost == "" {
		cfg.OriginHost = "swm-handler.localdomain"
	}
	if cfg.OriginRealm == "" {
		cfg.OriginRealm = "localdomain"
	}
	if cfg.ProductName == "" {
		cfg.ProductName = "swm-aaad"
	}
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = 2 * time.Minute
	}
	return &cfg, nil
}
