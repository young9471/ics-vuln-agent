// Command protocol-agent runs the Protocol Agent platform: the PostgreSQL stores, the
// PLAYBOOK P1-P6 pipeline runner, and the JSON HTTP API consumed by the
// shadcn/ui frontend.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Autumn-27/protocol-agent/agent"
	"github.com/Autumn-27/protocol-agent/config"
	"github.com/Autumn-27/protocol-agent/logx"
	"github.com/Autumn-27/protocol-agent/server"
)

// version is the build version, injected at release time via
// -ldflags "-X main.version=<tag>". Defaults to "dev" for local builds.
var version = "dev"

const banner = `
 ____            _                  _
|  _ \ _ __ ___ | |_ ___  _ __ ___ | |_
| |_) | '__/ _ \| __/ _ \| '__/ _ \| __|
|  __/| | | (_) | || (_) | | | (_) | |_
|_|   |_|  \___/ \__\___/|_|  \___/ \__|
`

// printBanner writes the startup banner + version/runtime info to stdout.
func printBanner(addr string) {
	fmt.Print(banner)
	fmt.Println("  工业私有协议逆向 Agent 平台")
	fmt.Printf("  版本 %s  ·  %s/%s  ·  %s  ·  监听 %s\n\n",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), addr)
}

// main maps run's result onto the process exit code.
func main() {
	os.Exit(run())
}

func run() int {
	var (
		addr    = flag.String("addr", ":8787", "HTTP listen address")
		dataDir = flag.String("data", filepath.Join(config.BaseDir(), "data"), "data directory (default: data/ next to the executable)")
		proxy   = flag.String("proxy", "", "traffic recording proxy address (empty to disable)")
		tlsCert = flag.String("tls-cert", os.Getenv("PROTOCOL_AGENT_TLS_CERT"), "TLS certificate file (with -tls-key enables HTTPS)")
		tlsKey  = flag.String("tls-key", os.Getenv("PROTOCOL_AGENT_TLS_KEY"), "TLS private key file")
	)
	flag.Parse()
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatalf("-tls-cert 和 -tls-key 必须同时提供")
	}
	if err := config.EnsureSecretKey(); err != nil {
		log.Fatalf("secret key: %v", err)
	}

	// hand the build version to the server package so GET /api/health can report it
	// to the frontend top bar.
	server.BuildVersion = version

	printBanner(*addr)

	// capture backend logs into the in-memory sink (still to stderr) so the /logs
	// page can show a live log stream. Do this first, to catch startup logs too.
	server.StartLogCapture()

	// Mirror logs to a rotated file as well; the sink above remains active so
	// /logs and the server_logs table keep receiving every line.
	if cleanupLogs, err := logx.Setup(*dataDir); err == nil {
		defer cleanupLogs()
	} else {
		log.Printf("[log] file logging disabled: %v", err)
	}

	// surface which config file the binary reads (absolute, so `go run`'s relative
	// "config.json" — resolved against the CWD — is unambiguous).
	cfgPath := config.Path()
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if _, e := os.Stat(cfgPath); e == nil {
		log.Printf("[config] 配置文件: %s", cfgPath)
	} else {
		log.Printf("[config] 配置文件: %s (不存在 — 将仅尝试环境变量 PROTOCOL_AGENT_PG_DSN)", cfgPath)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, shutdown := shutdownContext(sigCtx)
	defer shutdown(agent.AbortShutdown)

	mgr, err := server.NewManager(*dataDir, *proxy)
	if err != nil {
		log.Fatalf("open stores: %v", err)
	}
	defer mgr.Close()

	skillDir := config.SkillDir()
	if abs, err := filepath.Abs(skillDir); err == nil {
		skillDir = abs
	}
	log.Printf("[config] skill 目录: %s", skillDir)
	srv := server.New(ctx, mgr, skillDir, *dataDir, config.BaseDir())
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		scheme := "http"
		if *tlsCert != "" {
			scheme = "https"
		}
		log.Printf("Protocol Agent %s backend listening on %s://%s (data=%s)", version, scheme, *addr, *dataDir)
		var err error
		if *tlsCert != "" {
			err = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return 0
}

// shutdownContext deliberately does not derive from signalCtx. If it did, the
// parent's plain context.Canceled could win the race before AbortShutdown was
// attached to the child, losing the diagnostic cause in every running Agent.
func shutdownContext(signalCtx context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, shutdown := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-signalCtx.Done():
			shutdown(agent.AbortShutdown)
		case <-ctx.Done():
		}
	}()
	return ctx, shutdown
}
