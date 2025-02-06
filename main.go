package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"time"

	"github.com/LMBishop/gunnel/api/handlers"
	"github.com/LMBishop/gunnel/pkg/config"
	"github.com/LMBishop/gunnel/pkg/store"
	"github.com/LMBishop/gunnel/pkg/wireguard"
	"github.com/go-co-op/gocron/v2"
	"github.com/gorilla/mux"
)

func main() {
	u, err := user.Current()
	if err != nil {
		slog.Warn("cannot verify user is root", "error", err)
	} else if u.Uid != "0" {
		slog.Error("this program must be run as root to manage WireGuard")
		os.Exit(1)
	}

	_, err = os.Stat("/usr/share/dict/words")
	if err != nil {
		slog.Error("could not find dictionary file at /usr/share/dict/words (you need to install a wordlist first)", "error", err)
		os.Exit(1)
	}

	if err := run(); err != nil {
		slog.Error("Unhandled error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configService := config.NewService()
	err := configService.InitialiseConfig("/etc/gunnel/config.yaml", "config.yaml")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	wireguardService := wireguard.NewService()
	storeService := store.NewService()

	c := configService.Config()

	public, err := wireguardService.Up(c.WireGuard.InterfaceName, c.WireGuard.Network, c.WireGuard.Port)
	if err != nil {
		return fmt.Errorf("could not bring WireGuard interface up: %w", err)
	}
	slog.Info("interface up", "interface", c.WireGuard.InterfaceName, "publickey", public)

	r := mux.NewRouter()
	r.Host(c.Hostname).PathPrefix("/{port:[0-9]+}").HandlerFunc(handlers.NewPeer(storeService, wireguardService, configService))
	r.Host(c.Hostname).Path("/").HandlerFunc(handlers.Index(configService))
	r.Host(fmt.Sprintf("{subdomain}.%s", c.Hostname)).HandlerFunc(handlers.ReverseProxy(storeService))

	srv := make([]*http.Server, 1)
	if c.TLS.Enabled {
		srv[0] = startHttpsServer(r, c.TLS.Cert, c.TLS.Key)
		srv = append(srv, startHttpRedirect())
	} else {
		srv[0] = startHttpServer(r)
	}

	slog.Info("server started", "hostname", c.Hostname, "tls", c.TLS.Enabled)

	s, err := gocron.NewScheduler()
	if err != nil {
		return fmt.Errorf("could not create scheduler: %w", err)
	}

	// todo fix (and move to service)
	_, err = s.NewJob(gocron.CronJob("0 * * * *", false), gocron.NewTask(func() {
		unusedRules := storeService.GetUnusedRulesSince(time.Now().Add(-time.Duration(c.ExpireAfter)))

		if len(unusedRules) == 0 {
			return
		}

		slog.Info("removing unused tunnels", "count", len(unusedRules))

		for _, rule := range unusedRules {
			wireguardService.RemovePeer(rule.Peer)
			storeService.RemoveForwardingRule(rule.Slug)
		}
	}),
	)

	channel := make(chan os.Signal, 1)
	signal.Notify(channel, os.Interrupt)

	<-channel

	err = s.Shutdown()
	if err != nil {
		slog.Error("scheduler shutdown", "error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	for _, s := range srv {
		if err := s.Shutdown(ctx); err != nil {
			slog.Error("server shutdown", "error", err)
		}
	}

	err = wireguardService.Down()
	if err != nil {
		return fmt.Errorf("could not bring WireGuard interface down %w", err)
	}

	slog.Info("interface down", "interface", c.WireGuard.InterfaceName)

	return nil
}

func startHttpServer(router *mux.Router) *http.Server {
	srv := &http.Server{
		Handler:      router,
		Addr:         ":80",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("http server", "error", err)
		}
	}()

	return srv
}

func startHttpsServer(router *mux.Router, cert string, key string) *http.Server {
	srv := &http.Server{
		Handler:      router,
		Addr:         ":443",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServeTLS(cert, key); err != nil {
			slog.Error("https server", "error", err)
		}
	}()

	return srv
}

func startHttpRedirect() *http.Server {
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
		}),
		Addr:         ":80",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("http redirect server", "error", err)
		}
	}()

	return srv
}
