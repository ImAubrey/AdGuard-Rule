package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

type geoSiteBuilder struct {
	domains map[string]*router.Domain
}

func newGeoSiteBuilder() *geoSiteBuilder {
	return &geoSiteBuilder{domains: make(map[string]*router.Domain)}
}

func (b *geoSiteBuilder) add(domain *router.Domain) {
	if domain == nil || domain.Value == "" {
		return
	}
	key := fmt.Sprintf("%d\x00%s", domain.Type, domain.Value)
	b.domains[key] = domain
}

func (b *geoSiteBuilder) list() []*router.Domain {
	result := make([]*router.Domain, 0, len(b.domains))
	for _, domain := range b.domains {
		result = append(result, domain)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Value == result[j].Value {
			return result[i].Type < result[j].Type
		}
		return result[i].Value < result[j].Value
	})
	return result
}

func (g *generator) writeXrayOutputs(geositePath, geoipPath string) error {
	records := g.collector.collected()
	sites, skipped := buildGeoSites(records)
	geoSiteData, err := proto.Marshal(&router.GeoSiteList{Entry: sites})
	if err != nil {
		return fmt.Errorf("编码 geosite.dat 失败: %w", err)
	}
	if err := writeBinaryFile(geositePath, geoSiteData); err != nil {
		return fmt.Errorf("写入 geosite.dat 失败: %w", err)
	}

	geoIPData, err := buildGeoIP(records)
	if err != nil {
		return fmt.Errorf("编码 geoip.dat 失败: %w", err)
	}
	if err := writeBinaryFile(geoipPath, geoIPData); err != nil {
		return fmt.Errorf("写入 geoip.dat 失败: %w", err)
	}
	log.Printf("Xray dat 已生成: geosite=%s, geoip=%s, skipped=%d", geositePath, geoipPath, skipped)
	return nil
}

func writeBinaryFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func buildGeoSites(records []collectedRule) ([]*router.GeoSite, int) {
	builders := map[string]*geoSiteBuilder{
		"ADGUARD-ALL":    newGeoSiteBuilder(),
		"ADGUARD-BLOCK":  newGeoSiteBuilder(),
		"ADGUARD-ALLOW":  newGeoSiteBuilder(),
		"ADGUARD-DOMAIN": newGeoSiteBuilder(),
		"ADGUARD-REGEX":  newGeoSiteBuilder(),
		"ADGUARD-MODIFY": newGeoSiteBuilder(),
		"ALLOW":          newGeoSiteBuilder(),
	}
	skipped := 0
	for _, record := range records {
		entries := domainsFromRule(record)
		if len(entries) == 0 {
			skipped++
			continue
		}
		allow := strings.HasPrefix(strings.TrimSpace(record.raw), "@@")
		for _, entry := range entries {
			builders["ADGUARD-ALL"].add(entry)
			if allow {
				builders["ADGUARD-ALLOW"].add(entry)
				builders["ALLOW"].add(entry)
			} else {
				builders["ADGUARD-BLOCK"].add(entry)
				for _, category := range adguardOptionCategories(record.raw) {
					if _, exists := builders[category]; !exists {
						builders[category] = newGeoSiteBuilder()
					}
					builders[category].add(entry)
				}
			}
			switch record.typ {
			case ruleDomain, ruleHosts:
				builders["ADGUARD-DOMAIN"].add(entry)
			case ruleRegex:
				builders["ADGUARD-REGEX"].add(entry)
			case ruleModify:
				builders["ADGUARD-MODIFY"].add(entry)
			}
		}
	}

	names := make([]string, 0, len(builders))
	for name := range builders {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]*router.GeoSite, 0, len(names))
	for _, name := range names {
		result = append(result, &router.GeoSite{
			CountryCode: name,
			Domain:      builders[name].list(),
		})
	}
	return result, skipped
}

var xrayDomainPattern = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}`)

var xrayOptionCategoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

var ignoredXrayOptionCategories = map[string]struct{}{
	// badfilter 用于取消其他规则，不应作为一个独立的匹配类别。
	"badfilter": {},
}

func adguardOptionCategories(raw string) []string {
	separator := strings.IndexByte(raw, '$')
	if separator < 0 || separator+1 >= len(raw) {
		return nil
	}

	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, option := range strings.Split(raw[separator+1:], ",") {
		option = strings.TrimSpace(strings.ToLower(option))
		// ~script 表示排除 script 类型，不能安全地归入 SCRIPT。
		if strings.HasPrefix(option, "~") {
			continue
		}
		name, _, _ := strings.Cut(option, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ignored := ignoredXrayOptionCategories[name]; ignored || !xrayOptionCategoryPattern.MatchString(name) {
			continue
		}
		category := strings.ToUpper(name)
		if _, exists := seen[category]; exists {
			continue
		}
		seen[category] = struct{}{}
		result = append(result, category)
	}
	return result
}

func domainsFromRule(record collectedRule) []*router.Domain {
	content := clearRule(record.raw)
	if content == "" {
		return nil
	}

	if record.typ == ruleHosts {
		fields := strings.Fields(record.raw)
		if len(fields) < 2 {
			return nil
		}
		result := make([]*router.Domain, 0, len(fields)-1)
		for _, field := range fields[1:] {
			if domain := normalizeDomain(field); domain != "" {
				result = append(result, rootDomain(domain))
			}
		}
		return result
	}

	if record.typ == ruleRegex {
		if regexpValue := normalizeXrayRegexp(content); regexpValue != "" {
			return []*router.Domain{{Type: router.Domain_Regex, Value: regexpValue}}
		}
		return nil
	}

	if domain := normalizeDomain(content); domain != "" {
		return []*router.Domain{rootDomain(domain)}
	}

	// AdGuard 的修饰规则不是 Xray 原生格式；尽量提取其中的域名，保证
	// ||example.com^$script、URL 等常见规则仍能进入 dat。
	if domain := normalizeDomain(xrayDomainPattern.FindString(content)); domain != "" {
		return []*router.Domain{rootDomain(domain)}
	}
	if regexpValue := normalizeXrayRegexp(content); regexpValue != "" {
		return []*router.Domain{{Type: router.Domain_Regex, Value: regexpValue}}
	}
	return nil
}

func rootDomain(domain string) *router.Domain {
	return &router.Domain{Type: router.Domain_RootDomain, Value: domain}
}

func normalizeDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.Trim(value, "'\"()[]{}<>")
	value = strings.TrimSuffix(value, "^")
	value = strings.TrimSuffix(value, ".")
	if strings.Contains(value, "/") || strings.Contains(value, ":") || strings.Contains(value, "$") {
		return ""
	}
	if !xrayDomainPattern.MatchString(value) || xrayDomainPattern.FindString(value) != value {
		return ""
	}
	return value
}

func normalizeXrayRegexp(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && strings.HasPrefix(value, "/") && strings.HasSuffix(value, "/") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "/"), "/")
	}
	if value == "" {
		return ""
	}
	if _, err := regexp.Compile(value); err != nil {
		return ""
	}
	return value
}

func buildGeoIP(records []collectedRule) ([]byte, error) {
	entries := make(map[string]*router.CIDR)
	for _, record := range records {
		for _, field := range strings.Fields(record.raw) {
			cidr := parseCIDR(field)
			if cidr == nil {
				continue
			}
			key := fmt.Sprintf("%d:%s:%d", cidr.Prefix, cidr.Ip, len(cidr.Ip))
			entries[key] = cidr
		}
	}

	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	cidrs := make([]*router.CIDR, 0, len(keys))
	for _, key := range keys {
		cidrs = append(cidrs, entries[key])
	}
	return proto.Marshal(&router.GeoIPList{
		Entry: []*router.GeoIP{{CountryCode: "ADGUARD", Cidr: cidrs}},
	})
}

func parseCIDR(value string) *router.CIDR {
	value = strings.Trim(value, "'\"(),[]")
	if ip, network, err := net.ParseCIDR(value); err == nil {
		return makeCIDR(ip, network)
	}
	if ip := net.ParseIP(value); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return &router.CIDR{Ip: append([]byte(nil), ip4...), Prefix: 32}
		}
		ip16 := ip.To16()
		return &router.CIDR{Ip: append([]byte(nil), ip16...), Prefix: 128}
	}
	return nil
}

func makeCIDR(ip net.IP, network *net.IPNet) *router.CIDR {
	ip = network.IP
	if ip4 := ip.To4(); ip4 != nil {
		prefix, _ := network.Mask.Size()
		return &router.CIDR{Ip: append([]byte(nil), ip4...), Prefix: uint32(prefix)}
	}
	ip16 := ip.To16()
	prefix, _ := network.Mask.Size()
	return &router.CIDR{Ip: append([]byte(nil), ip16...), Prefix: uint32(prefix)}
}
