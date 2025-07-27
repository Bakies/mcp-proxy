package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type MiddlewareFunc func(http.Handler) http.Handler

func chainMiddleware(h http.Handler, middlewares ...MiddlewareFunc) http.Handler {
	for _, mw := range middlewares {
		h = mw(h)
	}
	return h
}

func newAuthMiddleware(tokens []string) MiddlewareFunc {
	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(tokens) != 0 {
				token := r.Header.Get("Authorization")
				token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
				if token == "" {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				if _, ok := tokenSet[token]; !ok {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func loggerMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("<%s> Request [%s] %s", prefix, r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

func recoverMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("<%s> Recovered from panic: %v", prefix, err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// metricsMiddleware adds Prometheus metrics for HTTP requests
func metricsMiddleware() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			path := r.URL.Path
			method := r.Method

			// Wrap the response writer to capture status code and response size
			rww := newResponseWriterWrapper(w)

			// Track request size
			if r.ContentLength > 0 {
				GetMetrics().requestSizeBytes.WithLabelValues(method, path).Observe(float64(r.ContentLength))
			}

			// Track in-progress requests
			GetMetrics().requestsInProgress.WithLabelValues(method, path).Inc()
			defer GetMetrics().requestsInProgress.WithLabelValues(method, path).Dec()

			// Call the next handler
			next.ServeHTTP(rww, r)

			// Record metrics after the request is complete
			duration := time.Since(start).Seconds()
			status := rww.statusCode

			GetMetrics().requestDuration.WithLabelValues(method, path).Observe(duration)
			GetMetrics().requestsTotal.WithLabelValues(method, path, fmt.Sprintf("%d", status)).Inc()
			
			if rww.bytesWritten > 0 {
				GetMetrics().responseSizeBytes.WithLabelValues(method, path).Observe(float64(rww.bytesWritten))
			}
		})
	}
}

// responseWriterWrapper wraps an http.ResponseWriter to capture metrics
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func newResponseWriterWrapper(w http.ResponseWriter) *responseWriterWrapper {
	return &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rww *responseWriterWrapper) WriteHeader(statusCode int) {
	rww.statusCode = statusCode
	rww.ResponseWriter.WriteHeader(statusCode)
}

func (rww *responseWriterWrapper) Write(p []byte) (int, error) {
	n, err := rww.ResponseWriter.Write(p)
	rww.bytesWritten += int64(n)
	return n, err
}

func startHTTPServer(config *Config) error {
	baseURL, uErr := url.Parse(config.McpProxy.BaseURL)
	if uErr != nil {
		return uErr
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpMux := http.NewServeMux()
	
	// Configure metrics based on configuration
	metricsEnabled := true
	metricsPath := "/metrics"
	
	if config.McpProxy.Options != nil && config.McpProxy.Options.Metrics != nil {
		metricsEnabled = config.McpProxy.Options.Metrics.Enabled && !config.McpProxy.Options.Metrics.DisableEndpoint
		if config.McpProxy.Options.Metrics.EndpointPath != "" {
			metricsPath = config.McpProxy.Options.Metrics.EndpointPath
		}
	}
	
	// Add Prometheus metrics endpoint if enabled
	if metricsEnabled {
		log.Printf("Adding metrics endpoint at %s", metricsPath)
		httpMux.Handle(metricsPath, promhttp.Handler())
	}
	
	// Add a simple health check endpoint
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	
	httpServer := &http.Server{
		Addr:    config.McpProxy.Addr,
		Handler: httpMux,
	}
	info := mcp.Implementation{
		Name: config.McpProxy.Name,
	}

	// Function to register a service with the HTTP server
	registerService := func(name string, mcpClient *Client, server *Server, clientConfig *MCPClientConfigV2) {
		middlewares := make([]MiddlewareFunc, 0)
		middlewares = append(middlewares, recoverMiddleware(name))
		
		// Add metrics middleware if enabled
		metricsEnabled := true
		if config.McpProxy.Options != nil && config.McpProxy.Options.Metrics != nil {
			metricsEnabled = config.McpProxy.Options.Metrics.Enabled
		}
		if metricsEnabled {
			middlewares = append(middlewares, metricsMiddleware())
		}
		
		if clientConfig.Options.LogEnabled.OrElse(false) {
			middlewares = append(middlewares, loggerMiddleware(name))
		}
		if len(clientConfig.Options.AuthTokens) > 0 {
			middlewares = append(middlewares, newAuthMiddleware(clientConfig.Options.AuthTokens))
		}
		mcpRoute := path.Join(baseURL.Path, name)
		if !strings.HasPrefix(mcpRoute, "/") {
			mcpRoute = "/" + mcpRoute
		}
		if !strings.HasSuffix(mcpRoute, "/") {
			mcpRoute += "/"
		}
		log.Printf("<%s> Handling requests at %s", name, mcpRoute)
		httpMux.Handle(mcpRoute, chainMiddleware(server.handler, middlewares...))
		httpServer.RegisterOnShutdown(func() {
			log.Printf("<%s> Shutting down", name)
			_ = mcpClient.Close()
		})
	}

	// Function to attempt connection and register service if successful
	tryConnectAndRegister := func(name string, mcpClient *Client, server *Server, clientConfig *MCPClientConfigV2) bool {
		log.Printf("<%s> Connecting", name)
		addErr := mcpClient.addToMCPServer(ctx, info, server.mcpServer)
		if addErr == nil {
			log.Printf("<%s> Connected", name)
			registerService(name, mcpClient, server, clientConfig)
			return true
		}
		log.Printf("<%s> Failed to connect: %v", name, addErr)
		return false
	}

	// Function to retry connection in background
	retryInBackground := func(name string, mcpClient *Client, server *Server, clientConfig *MCPClientConfigV2) {
		go func() {
			retryDelay := 5 * time.Second
			maxRetries := 50 // More retries since it's in background
			
			for attempt := 1; attempt <= maxRetries; attempt++ {
				select {
				case <-ctx.Done():
					return
				case <-time.After(retryDelay):
					log.Printf("<%s> Retry attempt %d/%d", name, attempt, maxRetries)
					if tryConnectAndRegister(name, mcpClient, server, clientConfig) {
						log.Printf("<%s> Successfully connected on retry attempt %d", name, attempt)
						return
					}
				}
			}
			log.Printf("<%s> Failed to connect after %d background retry attempts", name, maxRetries)
		}()
	}

	for name, clientConfig := range config.McpServers {
		mcpClient, err := newMCPClient(name, clientConfig)
		if err != nil {
			return err
		}
		server, err := newMCPServer(name, config.McpProxy, clientConfig)
		if err != nil {
			return err
		}
		
		// Try to connect once immediately
		if !tryConnectAndRegister(name, mcpClient, server, clientConfig) {
			// If initial connection fails, check if we should panic or retry in background
			if clientConfig.Options.PanicIfInvalid.OrElse(false) {
				return fmt.Errorf("failed to connect to required service: %s", name)
			}
			// Start background retries for this service
			retryInBackground(name, mcpClient, server, clientConfig)
		}
	}

	// Add /services endpoint for frontend API compatibility
	httpMux.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		// Build services list from config
		services := make([]map[string]interface{}, 0, len(config.McpServers))
		for name, clientConfig := range config.McpServers {
			service := map[string]interface{}{
				"name": name,
			}
			
			// Determine service type and add relevant fields
			if clientConfig.URL != "" {
				service["type"] = "sse"
				service["url"] = clientConfig.URL
			} else if clientConfig.Command != "" {
				service["type"] = "stdio" 
				service["command"] = clientConfig.Command
				if len(clientConfig.Args) > 0 {
					service["args"] = clientConfig.Args
				}
			} else {
				service["type"] = "http"
			}
			
			services = append(services, service)
		}
		
		response := map[string]interface{}{
			"services": services,
		}
		
		json.NewEncoder(w).Encode(response)
	})

	// Add stub Kubernetes API endpoints for frontend compatibility
	// These return empty lists since this server doesn't implement full K8s integration
	httpMux.HandleFunc("/api/v1/mcps", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		// Return empty list for now - this would be implemented by the K8s operator
		response := map[string]interface{}{
			"items": []map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(response)
	})
	
	httpMux.HandleFunc("/api/v1/mcpgroups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		// Return empty list for now - this would be implemented by the K8s operator  
		response := map[string]interface{}{
			"items": []map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(response)
	})

	// Add /paths endpoint to show available paths
	httpMux.HandleFunc("/paths", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		// Basic endpoints
		paths := map[string]string{
			"/health": "Health check endpoint",
			"/paths": "List of available API paths",
		}
		
		// Add metrics endpoint if enabled
		if metricsEnabled {
			paths[metricsPath] = "Prometheus metrics endpoint"
		}
		
		// Add MCP server paths with proper SSE endpoints
		for name := range config.McpServers {
			// Base route for the MCP server
			mcpRoute := path.Join(baseURL.Path, name)
			if !strings.HasPrefix(mcpRoute, "/") {
				mcpRoute = "/" + mcpRoute
			}
			if !strings.HasSuffix(mcpRoute, "/") {
				mcpRoute += "/"
			}
			
			// Add SSE endpoint (this is the main connection point)
			sseEndpoint := mcpRoute + "sse"
			paths[sseEndpoint] = fmt.Sprintf("SSE connection endpoint for %s MCP service", name)
			
			// Add Message endpoint (used internally by the SSE connection)
			messageEndpoint := mcpRoute + "message"
			paths[messageEndpoint] = fmt.Sprintf("Message endpoint for %s MCP service (used internally)", name)
		}
		
		response, _ := json.MarshalIndent(paths, "", "  ")
		w.Write(response)
	})
	
	// Log basic server info immediately
	log.Printf("MCP Proxy initialized")
	log.Printf("Basic API paths available:")
	log.Printf("- Health Check: /health")
	if metricsEnabled {
		log.Printf("- Metrics: %s", metricsPath)
	}
	log.Printf("- API Paths: /paths")
	log.Printf("- Services: /services")
	log.Printf("MCP services will be available at their respective endpoints as they connect")

	go func() {
		log.Printf("Starting SSE server")
		log.Printf("SSE server listening on %s", config.McpProxy.Addr)
		hErr := httpServer.ListenAndServe()
		if hErr != nil && !errors.Is(hErr, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", hErr)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()

	err := httpServer.Shutdown(shutdownCtx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}