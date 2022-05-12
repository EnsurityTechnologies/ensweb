package ensweb

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/EnsurityTechnologies/adapter"
	"github.com/EnsurityTechnologies/config"
	"github.com/EnsurityTechnologies/logger"
	"github.com/gorilla/mux"
)

const DefaultTimeout = 60 * time.Second

const (
	DefaultTokenHdr  string = "X-Token"
	DefaultRawErrHdr string = "X-Raw"
)

const (
	JSONContentType string = "application/json"
)

const (
	StatusSuccess string = "Success"
	StatusFailed  string = "Failed"
	StatusError   string = "Error"
	StatusBusy    string = "Busy"
	StatusNone    string = "None"
)

type HandlerFunc func(req *Request) *Result
type ShutdownFunc func() error

// Server defines server
type Server struct {
	cfg        *config.Config
	serverCfg  *ServerConfig
	s          *http.Server
	mux        *mux.Router
	log        logger.Logger
	auditLog   logger.Logger
	db         *adapter.Adapter
	url        string
	jwtSecret  string
	rootPath   string
	publicPath string
	apiKey     string
	ss         map[string]*SessionStore
	debugMode  bool
	sf         ShutdownFunc
}

type ServerConfig struct {
	AuthHeaderName   string
	RawErrHeaderName string
}

type ErrMessage struct {
	Error string `json:"Message"`
}

type StatusMsg struct {
	Status  string `json:"Status"`
	Message string `json:"Message"`
}

type ServerOptions = func(*Server) error

func SetServerTimeout(timeout time.Duration) ServerOptions {
	return func(s *Server) error {
		s.s.ReadTimeout = timeout
		s.s.WriteTimeout = timeout
		return nil
	}
}

// NewServer create new server instances
func NewServer(cfg *config.Config, serverCfg *ServerConfig, log logger.Logger, options ...ServerOptions) (Server, error) {
	if os.Getenv("ASPNETCORE_PORT") != "" {
		cfg.HostPort = os.Getenv("ASPNETCORE_PORT")
	}
	addr := net.JoinHostPort(cfg.HostAddress, cfg.HostPort)
	s := &http.Server{
		Addr:         addr,
		ReadTimeout:  DefaultTimeout,
		WriteTimeout: DefaultTimeout,
	}
	var serverURL string
	if cfg.Production == "false" {
		serverURL = "http://" + addr
	} else {
		serverURL = "https://" + addr
	}
	slog := log.Named("enswebserver")
	var db *adapter.Adapter
	var err error
	if cfg.DBType != "" {
		db, err = adapter.NewAdapter(cfg)
		if err != nil {
			slog.Error("failed to DB adapter", "err", err)
			return Server{}, err
		}
	}

	ts := Server{
		s:          s,
		cfg:        cfg,
		serverCfg:  serverCfg,
		mux:        mux.NewRouter(),
		log:        slog,
		db:         db,
		url:        serverURL,
		rootPath:   "views/",
		publicPath: "public/",
		ss:         make(map[string]*SessionStore),
	}

	for _, op := range options {
		err = op(&ts)
		if err != nil {
			slog.Error("failed in setting the option", "err", err)
			return Server{}, err
		}
	}

	return ts, nil
}

func (s *Server) SetDebugMode() {
	s.debugMode = true
}

func (s *Server) SetAuditLog(log logger.Logger) {
	s.auditLog = log
}

func (s *Server) SetAPIKey(apiKey string) {
	s.apiKey = apiKey
}

// Start starts the underlying HTTP server
func (s *Server) Start() error {
	// Setup the handler before starting
	s.s.Handler = s.mux
	s.log.Info(fmt.Sprintf("Starting Server at %s", s.s.Addr))
	if s.cfg.Production == "true" {
		go s.s.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
		return nil
	} else {
		go s.s.ListenAndServe()
		return nil
	}
}

func (s *Server) SetShutdown(sf ShutdownFunc) {
	s.sf = sf
}

// Shutdown attempts to gracefully shutdown the underlying HTTP server.
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	var err error
	if s.sf != nil {
		err = s.sf()
		if err != nil {
			return err
		}
	}
	return s.s.Shutdown(ctx)
}

// GetDB will return DB
func (s *Server) GetDB() *adapter.Adapter {
	return s.db
}
