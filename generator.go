package main

import (
	"bufio"
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultHTTPTimeout = 20 * time.Second
	maxRuleLineSize    = 4 * 1024 * 1024
)

type source struct {
	name   string
	remote bool
}

type generator struct {
	cfg       *config
	root      string
	client    *http.Client
	collector *collector
}

func newGenerator(cfg *config, root string) *generator {
	// 四类规则都会被收集：TXT 输出由配置决定，Xray dat 输出需要尽量覆盖全部规则。
	enabled := map[ruleType]bool{
		ruleDomain: true,
		ruleHosts:  true,
		ruleRegex:  true,
		ruleModify: true,
	}

	return &generator{
		cfg:  cfg,
		root: root,
		client: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
		collector: newCollector(enabled),
	}
}

func (g *generator) run(ctx context.Context) error {
	started := time.Now()
	plan, err := g.outputPlan()
	if err != nil {
		return err
	}

	header := buildHeader(g.cfg, started)
	if err := initializeOutputs(plan.text, header); err != nil {
		return err
	}

	sources := g.sources()
	if len(sources) == 0 {
		return fmt.Errorf("没有配置任何远程或本地规则源")
	}

	workers := runtime.NumCPU() * 2
	if workers < 1 {
		workers = 1
	}
	if workers > len(sources) {
		workers = len(sources)
	}
	jobs := make(chan source)
	errors := make(chan error, len(sources))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for src := range jobs {
				if err := g.processSource(ctx, src); err != nil {
					errors <- err
				}
			}
		}()
	}

	for _, src := range sources {
		select {
		case jobs <- src:
		case <-ctx.Done():
			break
		}
	}
	close(jobs)
	wg.Wait()
	close(errors)

	if ctx.Err() != nil {
		return ctx.Err()
	}
	for err := range errors {
		log.Printf("规则源处理失败: %v", err)
	}

	if err := g.writeOutputs(plan.text, header); err != nil {
		return err
	}
	if g.cfg.Application.Xray.enabled() {
		if err := g.writeXrayOutputs(plan.geosite, plan.geoip); err != nil {
			return err
		}
	}
	log.Printf("Done! %d ms, sources=%d, unique=%d", time.Since(started).Milliseconds(), len(sources), g.collector.count())
	return nil
}

func (g *generator) sources() []source {
	result := make([]source, 0, len(g.cfg.Application.Rule.Remote)+len(g.cfg.Application.Rule.Local))
	for _, url := range g.cfg.Application.Rule.Remote {
		if strings.TrimSpace(url) != "" {
			result = append(result, source{name: strings.TrimSpace(url), remote: true})
		}
	}
	for _, path := range g.cfg.Application.Rule.Local {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(g.root, "rule", path)
		}
		result = append(result, source{name: filepath.Clean(path)})
	}
	return result
}

type outputPlan struct {
	text    map[string]string
	geosite string
	geoip   string
}

func (g *generator) outputPlan() (*outputPlan, error) {
	base := g.cfg.Application.Output.Path
	if base == "" {
		base = "."
	}
	if !filepath.IsAbs(base) {
		base = filepath.Join(g.root, base)
	}

	paths := make(map[string]string, len(g.cfg.Application.Output.Files))
	for name := range g.cfg.Application.Output.Files {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("输出文件名不能为空")
		}
		paths[name] = filepath.Join(base, filepath.Clean(name))
	}
	plan := &outputPlan{text: paths}
	if g.cfg.Application.Xray.enabled() {
		plan.geosite = filepath.Join(base, filepath.Clean(g.cfg.Application.Xray.geositeName()))
		plan.geoip = filepath.Join(base, filepath.Clean(g.cfg.Application.Xray.geoipName()))
	}
	return plan, nil
}

func (g *generator) processSource(ctx context.Context, src source) error {
	started := time.Now()
	reader, closeReader, err := g.openSource(ctx, src)
	if err != nil {
		return fmt.Errorf("%s: %w", src.name, err)
	}
	defer closeReader()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxRuleLineSize)
	lineNumber := 0
	invalid := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		switch g.collector.process(line) {
		case lineInvalid:
			invalid++
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取失败: %w", err)
	}
	log.Printf("规则 <%s> 完成, lines=%d, invalid=%d, elapsed=%d ms", src.name, lineNumber, invalid, time.Since(started).Milliseconds())
	return nil
}

func (g *generator) openSource(ctx context.Context, src source) (io.Reader, func(), error) {
	if !src.remote {
		file, err := os.Open(src.name)
		if err != nil {
			return nil, func() {}, err
		}
		return file, func() { _ = file.Close() }, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, src.name, nil)
	if err != nil {
		return nil, func() {}, err
	}
	request.Header.Set("User-Agent", "adguardhome-rule-gen/1.0")
	response, err := g.client.Do(request)
	if err != nil {
		return nil, func() {}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_ = response.Body.Close()
		return nil, func() {}, fmt.Errorf("HTTP 状态码 %s", response.Status)
	}
	return response.Body, func() { _ = response.Body.Close() }, nil
}

func (g *generator) writeOutputs(paths map[string]string, header string) error {
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		file, err := os.Create(paths[name])
		if err != nil {
			return fmt.Errorf("创建输出文件 %q 失败: %w", paths[name], err)
		}
		writer := bufio.NewWriterSize(file, 1024*1024)
		if _, err := writer.WriteString(header); err != nil {
			_ = file.Close()
			return fmt.Errorf("写入输出文件 %q 失败: %w", paths[name], err)
		}

		lines := g.collector.lines(g.cfg.Application.Output.Files[name])
		for _, line := range lines {
			if _, err := writer.WriteString(line + "\r\n"); err != nil {
				_ = file.Close()
				return fmt.Errorf("写入输出文件 %q 失败: %w", paths[name], err)
			}
		}
		if err := writer.Flush(); err != nil {
			_ = file.Close()
			return fmt.Errorf("刷新输出文件 %q 失败: %w", paths[name], err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("关闭输出文件 %q 失败: %w", paths[name], err)
		}
	}
	return nil
}

func initializeOutputs(paths map[string]string, header string) error {
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("创建输出目录 %q 失败: %w", filepath.Dir(path), err)
		}
		file, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("创建输出文件 %q 失败: %w", path, err)
		}
		_, writeErr := file.WriteString(header)
		closeErr := file.Close()
		if writeErr != nil {
			return fmt.Errorf("初始化输出文件 %q 失败: %w", path, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("关闭输出文件 %q 失败: %w", path, closeErr)
		}
	}
	return nil
}

func buildHeader(cfg *config, at time.Time) string {
	var builder strings.Builder
	builder.WriteString("# Update time: ")
	builder.WriteString(at.Format("2006-01-02 15:04:05"))
	builder.WriteString("\r\n")
	builder.WriteString("# Repo URL: AdGuard、AdGuardHome广告过滤规则合并/去重\r\n\r\n")
	builder.WriteString("###################################   合并/去重自以下规则   ####################################\r\n")
	for _, url := range cfg.Application.Rule.Remote {
		if strings.TrimSpace(url) != "" {
			builder.WriteString("# - '")
			builder.WriteString(strings.TrimSpace(url))
			builder.WriteString("'\r\n")
		}
	}
	for _, path := range cfg.Application.Rule.Local {
		if strings.TrimSpace(path) != "" {
			builder.WriteString("# - local: '")
			builder.WriteString(strings.TrimSpace(path))
			builder.WriteString("'\r\n")
		}
	}
	builder.WriteString("###############################################################################################\r\n\r\n")
	builder.WriteString("# 每12小时同步一次、如有误杀、请手动解除\r\n\r\n")
	return builder.String()
}

type lineStatus uint8

const (
	lineSkipped lineStatus = iota
	lineInvalid
	lineAccepted
)

type dedupShard struct {
	sync.Mutex
	values map[string]struct{}
}

type deduper struct {
	shards []dedupShard
}

func newDeduper(shardCount int) *deduper {
	result := &deduper{shards: make([]dedupShard, shardCount)}
	for i := range result.shards {
		result.shards[i].values = make(map[string]struct{})
	}
	return result
}

func (d *deduper) first(value string) bool {
	index := crc32.ChecksumIEEE([]byte(value)) % uint32(len(d.shards))
	shard := &d.shards[index]
	shard.Lock()
	defer shard.Unlock()
	if _, exists := shard.values[value]; exists {
		return false
	}
	shard.values[value] = struct{}{}
	return true
}

type collector struct {
	deduper *deduper
	enabled map[ruleType]bool
	mu      sync.RWMutex
	rules   map[ruleType]map[string]struct{}
}

func newCollector(enabled map[ruleType]bool) *collector {
	rules := make(map[ruleType]map[string]struct{}, len(enabled))
	for typ := range enabled {
		rules[typ] = make(map[string]struct{})
	}
	return &collector{
		deduper: newDeduper(64),
		enabled: enabled,
		rules:   rules,
	}
}

func (c *collector) process(line string) lineStatus {
	if strings.TrimSpace(line) == "" {
		return lineSkipped
	}
	content := clearRule(line)
	if content == "" {
		return lineInvalid
	}
	if !c.deduper.first(line) {
		return lineSkipped
	}

	typ, ok := classifyRule(content)
	if !ok {
		return lineInvalid
	}
	if c.enabled[typ] {
		c.mu.Lock()
		c.rules[typ][line] = struct{}{}
		c.mu.Unlock()
	}
	return lineAccepted
}

func (c *collector) lines(types []ruleType) []string {
	seenTypes := make(map[ruleType]struct{}, len(types))
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, typ := range types {
		if _, exists := seenTypes[typ]; exists {
			continue
		}
		seenTypes[typ] = struct{}{}
		count += len(c.rules[typ])
	}
	lines := make([]string, 0, count)
	for typ := range seenTypes {
		for line := range c.rules[typ] {
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return lines
}

func (c *collector) count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := 0
	for _, rules := range c.rules {
		total += len(rules)
	}
	return total
}

type collectedRule struct {
	typ ruleType
	raw string
}

func (c *collector) collected() []collectedRule {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]collectedRule, 0)
	for typ, rules := range c.rules {
		for raw := range rules {
			result = append(result, collectedRule{typ: typ, raw: raw})
		}
	}
	return result
}

var (
	ineffectiveRulePattern = regexp.MustCompile(`^!|^#[^#,^@,^%,^\$]|^\[.*\]$`)
	basicModifyPattern     = regexp.MustCompile(`^(@@\|\||\|\||@@)|\$important$|\s#[^#]*$`)
	domainPattern          = regexp.MustCompile(`^([\w\d,-]+\.)+[\w\d,-]+(\^$)?$`)
	hostsPattern           = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+\s+.*$`)
	dollarPattern          = regexp.MustCompile(`\$[^\s]`)
	caretPattern           = regexp.MustCompile(`\^[^\s]`)
)

func clearRule(content string) string {
	content = strings.TrimSpace(content)
	if content == "" || ineffectiveRulePattern.MatchString(content) {
		return ""
	}
	content = basicModifyPattern.ReplaceAllString(content, "")
	return strings.TrimSpace(content)
}

func classifyRule(rule string) (ruleType, bool) {
	if domainPattern.MatchString(rule) {
		return ruleDomain, true
	}
	if hostsPattern.MatchString(rule) {
		return ruleHosts, true
	}
	if validRegexRule(rule) {
		return ruleRegex, true
	}
	return ruleModify, true
}

func validRegexRule(rule string) bool {
	if strings.ContainsAny(rule, "/,#&=:") {
		return false
	}
	if rule != "" && strings.ContainsRune("*,@,-_.,&?", []rune(rule)[0]) {
		return false
	}
	return !dollarPattern.MatchString(rule) && !caretPattern.MatchString(rule)
}
