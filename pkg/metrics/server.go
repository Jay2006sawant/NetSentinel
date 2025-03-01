package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Server manages the metrics HTTP server
type Server struct {
	// HTTP server
	server *http.Server
	// Logger
	log *logrus.Logger
}

// NewServer creates a new metrics server
func NewServer(addr string) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return &Server{
		server: server,
		log:    logrus.New(),
	}
}

// Start begins serving metrics
func (s *Server) Start() error {
	s.log.WithField("addr", s.server.Addr).Info("Starting metrics server")
	return s.server.ListenAndServe()
}

// Stop gracefully shuts down the server
func (s *Server) Stop(ctx context.Context) error {
	s.log.Info("Stopping metrics server")
	return s.server.Shutdown(ctx)
} 