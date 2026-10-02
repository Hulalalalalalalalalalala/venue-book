package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const product = "VenueBook"
const resourceName = "venues"
const page = "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>VenueBook · 场地预约与活动报名</title><style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.7}a{color:#175b9c}</style><main><h1>VenueBook</h1><p>场地预约与活动报名</p><h2>场地列表</h2><p>还没有场地记录。</p><p><a href=\"/api/venues\">查看场地列表接口</a> · <a href=\"/health\">服务状态</a></p></main></html>"

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if status == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", "GET")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func run() error {
	if len(os.Args) < 2 {
		printHelp()
		return errors.New("expected serve or --help")
	}
	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		printHelp()
		return nil
	}
	if os.Args[1] != "serve" {
		return errors.New("expected serve or --help")
	}
	args := flag.NewFlagSet("venue-book serve", flag.ContinueOnError)
	args.SetOutput(os.Stdout)
	host := args.String("host", "127.0.0.1", "address to bind")
	port := args.Int("port", 8080, "port to bind; 0 selects an available port")
	data := args.String("data-dir", "data", "directory for local records")
	if err := args.Parse(os.Args[2:]); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if args.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if *port < 0 || *port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	if err := os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	dataFile := filepath.Join(*data, "venues.json")
	file, err := os.OpenFile(dataFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, writeErr := file.WriteString("[]\n")
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.URL.Path
		if route != "/" && route != "/health" && route != "/api/venues" {
			respond(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if r.Method != http.MethodGet {
			respond(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if route == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, page)
			return
		}
		if route == "/health" {
			respond(w, http.StatusOK, map[string]string{"status": "ok", "product": product})
			return
		}
		raw, err := os.ReadFile(dataFile)
		var records []json.RawMessage
		if err == nil {
			err = json.Unmarshal(raw, &records)
		}
		if err != nil || records == nil {
			respond(w, http.StatusInternalServerError, map[string]string{"error": "unable to read venues"})
			return
		}
		respond(w, http.StatusOK, map[string]any{resourceName: records})
	})
	listener, err := net.Listen("tcp", net.JoinHostPort(*host, fmt.Sprint(*port)))
	if err != nil {
		return err
	}
	fmt.Printf("%s listening on http://%s\n", product, listener.Addr().String())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, 1)
	go func() { failures <- server.Serve(listener) }()
	select {
	case err := <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
	}
	return nil
}

func printHelp() {
	fmt.Println("VenueBook - 场地预约与活动报名")
	fmt.Println("Usage: go run . serve [--host ADDRESS] [--port PORT] [--data-dir DIRECTORY]")
	fmt.Println("       go run . --help")
	fmt.Println("Defaults: --host 127.0.0.1 --port 8080 --data-dir data")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
