package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ruleType string

const (
	ruleDomain ruleType = "DOMAIN"
	ruleHosts  ruleType = "HOSTS"
	ruleRegex  ruleType = "REGEX"
	ruleModify ruleType = "MODIFY"
)

func (t *ruleType) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}

	parsed := ruleType(strings.ToUpper(strings.TrimSpace(raw)))
	switch parsed {
	case ruleDomain, ruleHosts, ruleRegex, ruleModify:
		*t = parsed
		return nil
	default:
		return fmt.Errorf("未知规则类型 %q", raw)
	}
}

type config struct {
	Application applicationConfig `yaml:"application"`
}

type applicationConfig struct {
	Rule   ruleConfig   `yaml:"rule"`
	Output outputConfig `yaml:"output"`
	Xray   xrayConfig   `yaml:"xray"`
}

type ruleConfig struct {
	Remote []string `yaml:"remote"`
	Local  []string `yaml:"local"`
}

type outputConfig struct {
	Path  string                `yaml:"path"`
	Files map[string][]ruleType `yaml:"files"`
}

type xrayConfig struct {
	Enabled *bool  `yaml:"enabled"`
	Geosite string `yaml:"geosite"`
	GeoIP   string `yaml:"geoip"`
}

func (x xrayConfig) enabled() bool {
	return x.Enabled == nil || *x.Enabled
}

func (x xrayConfig) geositeName() string {
	if strings.TrimSpace(x.Geosite) == "" {
		return "geosite.dat"
	}
	return strings.TrimSpace(x.Geosite)
}

func (x xrayConfig) geoipName() string {
	if strings.TrimSpace(x.GeoIP) == "" {
		return "geoip.dat"
	}
	return strings.TrimSpace(x.GeoIP)
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %q 失败: %w", path, err)
	}

	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 %q 失败: %w", path, err)
	}
	if len(cfg.Application.Output.Files) == 0 {
		return nil, fmt.Errorf("配置 application.output.files 不能为空")
	}
	return &cfg, nil
}
