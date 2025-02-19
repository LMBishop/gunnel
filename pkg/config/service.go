package config

import (
	"fmt"
	"net"
	"os"
	"regexp"

	validate "github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Hostname string `yaml:"host" validate:"required"`
	TLS      struct {
		Enabled bool   `yaml:"enabled"`
		Cert    string `yaml:"cert"`
		Key     string `yaml:"key"`
	} `yaml:"tls"`
	WireGuard struct {
		Network       string `yaml:"network" validate:"cidr,required"`
		Port          string `yaml:"port" validate:"required"`
		InterfaceName string `yaml:"interfaceName" validate:"required"`
	} `yaml:"wireGuard"`
	Permissions struct {
		Enabled   bool   `yaml:"enabled"`
		SecretKey string `yaml:"secretKey"`
	}
	ExpireAfter int `yaml:"expireAfter"`
}

type Service interface {
	InitialiseConfig(paths ...string) error
	Config() *Config
}

type service struct {
	config    *Config
	validator *validate.Validate
}

const InterfaceRegex = "^[a-zA-Z0-9_=+.-]{1,15}$"

func NewService() Service {
	return &service{
		validator: validate.New(validate.WithRequiredStructEnabled()),
	}
}

func (s *service) InitialiseConfig(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		c := &Config{}
		err := readConfig(p, c)
		if err != nil {
			return err
		}
		s.config = c
		break
	}
	return nil
}

func (s *service) Config() *Config {
	return s.config
}

func readConfig(configPath string, dst *Config) error {
	config, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(config, dst); err != nil {
		return err
	}
	return nil
}

func (s *service) validateConfig(c *Config) error {
	if err := s.validator.Struct(c); err != nil {
		return err
	}

	match, _ := regexp.MatchString(InterfaceRegex, c.WireGuard.InterfaceName)
	if !match {
		return fmt.Errorf("invalid interface name: %s", c.WireGuard.InterfaceName)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("could not list network interfaces: %w", err)
	}
	for _, i := range ifaces {
		if i.Name == c.WireGuard.InterfaceName {
			return fmt.Errorf("an interface already exists with the name '%s'", i.Name)
		}
	}

	if c.Permissions.Enabled && len(c.Permissions.SecretKey) == 0 {
		return fmt.Errorf("requested permissioned setup but no secret key was given")
	}

	return nil
}
