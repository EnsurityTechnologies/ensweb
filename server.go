package ensweb

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/EnsurityTechnologies/enscrypt"
	"github.com/EnsurityTechnologies/logger"
	"github.com/EnsurityTechnologies/uuid"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

const DefaultTimeout = 60 * time.Second

const (
	DefaultTokenHdr  string = "X-Token"
	DefaultRawErrHdr string = "X-Raw"
	PublicKeyHdr     string = "publickey"
	RequestIDHdr     string = "requestid"
	LicenseKeyHdr    string = "licensekey"
)
const (
	GetPublicKeyAPI string = "/api/getpublickey"
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
type AuthFunc func(req *Request) bool
type ShutdownFunc func() error
type GetTenantCBFunc func(tenantName string) uuid.UUID

// Server defines server
type Server struct {
	cfg             *Config
	serverCfg       *ServerConfig
	s               *http.Server
	mux             *mux.Router
	log             logger.Logger
	auditLog        logger.Logger
	db              *gorm.DB
	url             string
	jwtSecret       string
	rootPath        string
	publicPath      string
	prefixPath      string
	apiKey          string
	secureAPI       bool
	pk              *ecdh.PrivateKey
	publicKey       string
	licenseKey      string
	ss              map[string]*SessionStore
	debugMode       bool
	sf              ShutdownFunc
	defaultTenantID uuid.UUID
	tcb             GetTenantCBFunc
}

type ServerConfig struct {
	AuthHeaderName   string
	RawErrHeaderName string
}

// ErrMessage example
type ErrMessage struct {
	Error string `json:"Message"`
}

type StatusMsg struct {
	Status  string `json:"Status"`
	Message string `json:"Message"`
}

type SecureData struct {
	Data string `json:"Data"`
}

type ServerOptions = func(*Server) error

func SetServerTimeout(timeout time.Duration) ServerOptions {
	return func(s *Server) error {
		s.s.IdleTimeout = timeout
		s.s.ReadTimeout = timeout
		s.s.WriteTimeout = timeout
		return nil
	}
}

func SetDB(db *gorm.DB) ServerOptions {
	return func(s *Server) error {
		s.db = db
		return nil
	}
}

func EnableSecureAPI(pk *ecdh.PrivateKey, licenseKey string) ServerOptions {
	return func(s *Server) error {
		s.secureAPI = true
		s.licenseKey = licenseKey
		if s.pk == nil {
			key, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				s.log.Error("failed to generate private key")
				return err
			}
			s.pk = key
		} else {
			s.pk = pk
		}
		pub := s.pk.PublicKey().Bytes()
		s.publicKey = base64.StdEncoding.EncodeToString(pub)
		return nil
	}
}

// NewServer create new server instances
func NewServer(cfg *Config, serverCfg *ServerConfig, log logger.Logger, options ...ServerOptions) (Server, error) {
	// if IIS configured port run the server on localhost
	if os.Getenv("ASPNETCORE_PORT") != "" {
		cfg.Address = "localhost"
		cfg.Port = os.Getenv("ASPNETCORE_PORT")
		cfg.Secure = false
	}
	addr := net.JoinHostPort(cfg.Address, cfg.Port)
	s := &http.Server{
		Addr:         addr,
		IdleTimeout:  DefaultTimeout,
		ReadTimeout:  DefaultTimeout,
		WriteTimeout: DefaultTimeout,
	}
	var serverURL string
	if cfg.Secure {
		serverURL = "https://" + addr
		if cfg.CertFile == "" {
			cfg.CertFile = "server.crt"
		}
		if cfg.KeyFile == "" {
			cfg.KeyFile = "server.key"
		}
	} else {
		serverURL = "http://" + addr
	}
	slog := log.Named("enswebserver")

	ts := Server{
		s:          s,
		cfg:        cfg,
		serverCfg:  serverCfg,
		mux:        mux.NewRouter(),
		log:        slog,
		url:        serverURL,
		rootPath:   "views/",
		publicPath: "public/",
		ss:         make(map[string]*SessionStore),
	}

	for _, op := range options {
		err := op(&ts)
		if err != nil {
			slog.Error("failed in setting the option", "err", err)
			return Server{}, err
		}
	}

	if ts.secureAPI {
		ts.AddRoute(GetPublicKeyAPI, "GET", ts.getPublicKeyAPI)
	}

	return ts, nil
}

// ShowAccount godoc
// @Summary      Get the public key of the server
// @Description  Get the public key of the server
// @Tags         general
// @Accept       json
// @Produce      json
// @Success      200 {object}  PublicKeyResponse
// @Router       /api/getpublickey [get]
func (s *Server) getPublicKeyAPI(req *Request) *Result {
	pr := PublicKeyResponse{
		BaseResponse: BaseResponse{
			Status: true,
		},
		PublicKey: s.publicKey,
	}
	return s.RenderNormalJSON(req, pr, http.StatusOK)
}

func (s *Server) IsSecureAPIEnabled() bool {
	return s.secureAPI
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
	ln, err := net.Listen("tcp", s.s.Addr)
	if err != nil {
		return err
	}
	connPort := fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
	if connPort != s.cfg.Port {
		s.log.Info("Requested port is not available, using the other port", "port", connPort)
		s.cfg.Port = connPort
		addr := net.JoinHostPort(s.cfg.Address, s.cfg.Port)
		serverURL := "http://" + addr
		if s.cfg.Secure {
			serverURL = "https://" + addr
		}
		s.url = serverURL
	}
	str := fmt.Sprintf("Server running at : %s", s.url)
	s.log.Info(str)
	if s.cfg.Secure {
		go s.s.ServeTLS(ln, s.cfg.CertFile, s.cfg.KeyFile)
		//go s.s.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
		return nil
	} else {
		go s.s.Serve(ln)
		//go s.s.ListenAndServe()
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

func (s *Server) SetDefaultTenant(id uuid.UUID) {
	s.defaultTenantID = id
}

func (s *Server) SetTenantCBFunc(tcb GetTenantCBFunc) {
	s.tcb = tcb
}

// GetDB will return DB
func (s *Server) GetDB() *gorm.DB {
	return s.db
}

// GetDB will return DB
func (s *Server) GetServerURL() string {
	return s.url
}

func (s *Server) getSharedSecret(req *Request) error {
	if req.ss != "" {
		return nil
	}
	pubkey := s.GetReqHeader(req, PublicKeyHdr)
	s.log.Info("public key : " + pubkey)
	pb, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		s.log.Error("invalid pubkey, failed to decode base 64 string", "err", err)
		return err
	}
	pub, err := ecdh.P256().NewPublicKey(pb)
	if err != nil {
		s.log.Error("invalid pubkey, failed to frame pubkey", "err", err)
		return err
	}
	kb, err := s.pk.ECDH(pub)
	if err != nil {
		s.log.Error("failed to create shared secret", "err", err)
		return err
	}
	ss := sha256.Sum256(kb)
	req.ss = hex.EncodeToString(ss[:])
	return nil
}

func encryptModel(ss string, model interface{}) (string, error) {
	data, err := json.Marshal(model)
	if err != nil {
		return "", err
	}
	eb, err := enscrypt.Seal(ss, data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(eb), nil
}

func decryptModel(ss string, data string, model interface{}) error {
	eb, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	db, err := enscrypt.UnSeal(ss, eb)
	if err != nil {
		return err
	}
	err = json.Unmarshal(db, model)
	if err != nil {
		return err
	}
	return nil
}
