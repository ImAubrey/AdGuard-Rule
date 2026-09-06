package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func TestRuleClassification(t *testing.T) {
	tests := []struct {
		line string
		want ruleType
	}{
		{line: "||example.com^", want: ruleDomain},
		{line: "0.0.0.0 ads.example.com", want: ruleHosts},
		{line: "example.com/path", want: ruleModify},
		{line: "example.com^$important", want: ruleDomain},
	}

	for _, test := range tests {
		content := clearRule(test.line)
		got, ok := classifyRule(content)
		if !ok || got != test.want {
			t.Fatalf("classifyRule(%q) = %q, %v; want %q", test.line, got, ok, test.want)
		}
	}
	if clearRule("! comment") != "" {
		t.Fatal("comment should be ignored")
	}
}

func TestLoadDefaultConfig(t *testing.T) {
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Application.Rule.Remote) == 0 || len(cfg.Application.Output.Files) == 0 {
		t.Fatal("default config did not load rule sources and output files")
	}
	if !cfg.Application.Xray.enabled() {
		t.Fatal("Xray output should be enabled by default config")
	}
}

func TestRunWritesTxtAndXrayDat(t *testing.T) {
	root := t.TempDir()
	ruleDir := filepath.Join(root, "rule")
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ruleDir, "input.txt"), []byte(strings.Join([]string{
		"! comment",
		"||example.com^",
		"||script.example.com^$script,third-party",
		"0.0.0.0 ads.example.com",
		"@@||allow.example.com^",
		"/track[0-9]+\\.example\\.org/",
		"||path.example.com/foo",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config{}
	cfg.Application.Rule.Local = []string{"input.txt"}
	cfg.Application.Output.Path = "out"
	cfg.Application.Output.Files = map[string][]ruleType{
		"all.txt": {ruleDomain, ruleHosts, ruleRegex, ruleModify},
	}

	if err := newGenerator(cfg, root).run(context.Background()); err != nil {
		t.Fatal(err)
	}

	all, err := os.ReadFile(filepath.Join(root, "out", "all.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"||example.com^", "ads.example.com", "@@||allow.example.com^"} {
		if !strings.Contains(string(all), expected) {
			t.Errorf("all.txt does not contain %q", expected)
		}
	}

	geositeData, err := os.ReadFile(filepath.Join(root, "out", "geosite.dat"))
	if err != nil {
		t.Fatal(err)
	}
	var geosite router.GeoSiteList
	if err := proto.Unmarshal(geositeData, &geosite); err != nil {
		t.Fatalf("geosite.dat is not valid Xray protobuf: %v", err)
	}
	for _, name := range []string{"ADGUARD-ALL", "SCRIPT", "THIRD-PARTY", "ALLOW"} {
		if !hasGeoSite(&geosite, name) {
			t.Fatalf("geosite.dat does not contain %s", name)
		}
	}

	geoipData, err := os.ReadFile(filepath.Join(root, "out", "geoip.dat"))
	if err != nil {
		t.Fatal(err)
	}
	var geoip router.GeoIPList
	if err := proto.Unmarshal(geoipData, &geoip); err != nil {
		t.Fatalf("geoip.dat is not valid Xray protobuf: %v", err)
	}
	if len(geoip.Entry) != 1 || geoip.Entry[0].CountryCode != "ADGUARD" || len(geoip.Entry[0].Cidr) == 0 {
		t.Fatalf("unexpected geoip.dat contents: %+v", geoip.Entry)
	}
}

func hasGeoSite(list *router.GeoSiteList, name string) bool {
	for _, site := range list.Entry {
		if site.CountryCode == name && len(site.Domain) > 0 {
			return true
		}
	}
	return false
}
