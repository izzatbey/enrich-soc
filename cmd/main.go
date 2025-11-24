package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/izzatbey/enrich-soc/internal/config"
	"github.com/izzatbey/enrich-soc/internal/enrich"
	"github.com/izzatbey/enrich-soc/internal/enricher"
)

func main() {
	cfg := config.Load()
	enr := enricher.New(cfg)

	svc, err := enrich.New(cfg, enr)
	if err != nil {
		log.Fatalf("failed to init service: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	svc.Run(ctx)
}
