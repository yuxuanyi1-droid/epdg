// Command epdgd is the Go control plane of the SWu ePDG. It terminates IKEv2
// through strongSwan, authenticates UEs with EAP-AKA over RADIUS against PyHSS
// derived vectors, and drives the S2b control plane towards Open5GS.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"epdg/internal/aaa"
	"epdg/internal/config"
	"epdg/internal/hss"
	"epdg/internal/ipsec"
	"epdg/internal/s2b"
	"epdg/internal/server"
)

func main() {
	configPath := flag.String("config", "configs/epdg/epdg.yaml", "path to the ePDG YAML configuration")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn or error")
	flag.Parse()

	logger, err := newLogger(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "epdgd:", err)
		os.Exit(2)
	}
	slog.SetDefault(logger)

	if err := run(*configPath, logger); err != nil {
		logger.Error("epdgd stopped with an error", "error", err)
		os.Exit(1)
	}
}

func run(path string, logger *slog.Logger) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	logger.Info("configuration loaded",
		"path", path, "node", cfg.NodeID,
		"ipsec", cfg.IPSec.Backend, "aaa", cfg.AAA.Backend,
		"radius", cfg.RADIUS.Backend, "s2b", cfg.Protocol.S2b.Backend,
		"plmn", cfg.Protocol.PLMN.String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var hssClient *hss.Client
	if cfg.AAA.Backend == "pyhss_api" {
		hssClient = hss.New(cfg.AAA.PyHSS.BaseURL, cfg.AAA.PyHSS.VectorPathTemplate,
			cfg.AAA.PyHSS.OAMPingPath, cfg.AAA.PyHSS.Timeout())
	}

	ipsecBackend, err := ipsec.New(cfg.IPSec)
	if err != nil {
		return err
	}
	defer ipsecBackend.Close()
	if err := ipsecBackend.Load(ctx); err != nil {
		// A missing charon is not fatal: the ePDG still answers its API and the
		// readiness report will show the failure.
		logger.Warn("cannot load the swanctl configuration at start up", "error", err)
	}

	s2bBackend, err := s2b.New(cfg.Protocol.S2b, cfg.Protocol.PLMN, logger)
	if err != nil {
		return err
	}

	var radiusServer *aaa.Server
	if cfg.RADIUS.Backend == "eap_aka" {
		if hssClient == nil {
			return errors.New("radius backend eap_aka requires aaa backend pyhss_api")
		}
		radiusServer = aaa.NewServer(aaa.ServerConfig{
			Listen:                      cfg.RADIUS.Listen,
			Secret:                      cfg.RADIUS.Secret,
			Realm:                       cfg.RADIUS.Realm,
			RequireMessageAuthenticator: cfg.RADIUS.RequireMessageAuthenticator,
			SendCheckcode:               cfg.RADIUS.SendCheckcode,
			MaxRounds:                   cfg.AAA.EAPMaxRounds,
		}, hssClient, logger.With("component", "radius"))

		errCh := make(chan error, 1)
		go func() {
			if err := radiusServer.ListenAndServe(ctx); err != nil {
				errCh <- err
			}
		}()
		select {
		case err := <-errCh:
			return fmt.Errorf("radius server failed to start: %w", err)
		case <-time.After(150 * time.Millisecond):
		}
	}

	app := server.NewApp(server.Options{
		Config: cfg,
		Logger: logger,
		IPSec:  ipsecBackend,
		HSS:    hssClient,
		Radius: radiusServer,
		S2B:    s2bBackend,
	})
	return app.ListenAndServe(ctx)
}

func newLogger(level string) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "", "info":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown log level %q", level)
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler), nil
}
