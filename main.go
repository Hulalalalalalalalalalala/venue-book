package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const product = "VenueBook"
const resourceName = "venues"

//go:embed index.html
var page string

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func errorJSON(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// allowedMethods 列出每个已知路径实际支持的方法。
var allowedMethods = map[string]string{
	"/":           "GET",
	"/health":     "GET",
	"/api/venues": "GET, POST",
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
	records, err := newStore(*data)
	if err != nil {
		return err
	}
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           newHandler(records),
	}
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

func newHandler(records *store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.URL.Path
		allow, known := allowedMethods[route]
		if !known {
			errorJSON(w, http.StatusNotFound, "not found")
			return
		}
		if route == "/api/venues" {
			switch r.Method {
			case http.MethodGet:
				handleListVenues(w, r, records)
				return
			case http.MethodPost:
				handleCreateVenue(w, r, records)
				return
			default:
				w.Header().Set("Allow", allow)
				errorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", allow)
			errorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if route == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, page)
			return
		}
		// /health
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "product": product})
	})
}

func handleListVenues(w http.ResponseWriter, _ *http.Request, records *store) {
	venues, err := records.list()
	if err != nil {
		// 读不到或数据损坏时返回 500，绝不能回写空列表覆盖已有记录。
		errorJSON(w, http.StatusInternalServerError, "unable to read venues")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{resourceName: venues})
}

func handleCreateVenue(w http.ResponseWriter, r *http.Request, records *store) {
	// 限制请求体大小，避免异常大请求占用内存。
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var payload map[string]any
	decoder := json.NewDecoder(r.Body)
	// 容量等整数字段必须按 JSON 数字的原文逐位判断：UseNumber 让数字以
	// json.Number（原始文本）保留，避免 float64 舍入把 120.00000000000000001
	// 变成 120、把 9007199254740993 变成相邻整数。
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		errorJSON(w, http.StatusBadRequest, "请求体不是有效的 JSON 对象："+err.Error())
		return
	}
	// 拒绝同一请求体中的多余 JSON 值（如 {} {}）。
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		errorJSON(w, http.StatusBadRequest, "请求体中存在多余的 JSON 内容")
		return
	}
	if payload == nil {
		errorJSON(w, http.StatusBadRequest, "请求体必须是 JSON 对象")
		return
	}

	venue, err := records.create(payload)
	if err != nil {
		var bad *apiError
		if errors.As(err, &bad) {
			errorJSON(w, http.StatusBadRequest, bad.Error())
			return
		}
		// 读不到已有数据、数据损坏或保存失败：不增加任何记录。
		errorJSON(w, http.StatusInternalServerError, "unable to save venue")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"venue": venue})
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
