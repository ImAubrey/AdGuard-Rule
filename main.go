package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
)

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	root, err := os.Getwd()
	if err != nil {
		log.Fatal(fmt.Errorf("获取工作目录失败: %w", err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := newGenerator(cfg, root).run(ctx); err != nil {
		log.Fatal(err)
	}
}
