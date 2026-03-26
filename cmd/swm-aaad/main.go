package main

import (
	"flag"
	"log"

	"epdg-go/internal/diameter"
	"epdg-go/internal/swmaaa"
)

func main() {
	configPath := flag.String("config", "configs/swm-aaad.yaml", "path to swm aaa yaml config")
	flag.Parse()

	cfg, err := swmaaa.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	logger := log.Default()
	handler := swmaaa.NewHandler(cfg, logger)
	server := diameter.NewServer(diameter.ServerConfig{
		Listen:      cfg.Listen,
		OriginHost:  cfg.OriginHost,
		OriginRealm: cfg.OriginRealm,
		ProductName: cfg.ProductName,
		ReadTimeout: cfg.ReadTimeout,
	}, handler, logger)

	log.Printf("starting swm aaad on %s as %s", cfg.Listen, cfg.OriginHost)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("swm aaad stopped: %v", err)
	}
}
