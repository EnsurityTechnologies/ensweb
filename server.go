package ensweb

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/EnsurityTechnologies/certs"
	"github.com/EnsurityTechnologies/logger"
	"github.com/EnsurityTechnologies/uuid"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/gorilla/mux"
	"github.com/jefferai/isbadcipher"
	"gorm.io/gorm"
)

const (
	DefaultTimeout           = 60 * time.Second
	DefaultIdleTimeout       = 5 * time.Minute
	DefaultReadTimeout       = 10 * time.Second
	DefaultReadHeaderTimeout = 5 * time.Second
)

const (
	DefaultTokenHdr  string = "X-Token"
	DefaultRawErrHdr string = "X-Raw"
	PublicKeyHdr     string = "publickey"
	RequestIDHdr     string = "requestid"
	LicenseKeyHdr    string = "licensekey"
)
const (
	GetPublicKeyAPI   string = "/api/getpublickey"
	GetPublicKeyAPIV2 string = "/api/v2/getpublickey"
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
type GetTenantCBFunc func(tenantName string) string

// Server defines server
type Server struct {
	cfg              *Config
	serverCfg        *ServerConfig
	s                *http.Server
	mux              *mux.Router
	log              logger.Logger
	auditLog         logger.Logger
	db               *gorm.DB
	url              string
	jwtSecret        string
	rootDir          string
	prefixPath       string
	apiKey           string
	secureAPI        bool
	pk               *ecdh.PrivateKey
	npk              *secp256k1.PrivateKey
	publicKey        string
	newPublicKey     string
	licenseKey       string
	ss               map[string]*SessionStore
	debugMode        bool
	allowHeaders     string
	sf               ShutdownFunc
	defaultTenantID  uuid.UUID
	tcb              GetTenantCBFunc
	tlsCert          *certs.TLSCertificate
	tlsConfig        *tls.Config
	defaultHeaders   map[string]string
	unProtectedPaths []string
	subDirectory     string
	rbac             RBACInterface
	rolePermisions   map[string]map[string][]string
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

func EnableRBAC(db *gorm.DB, rbac RBACInterface) ServerOptions {
	return func(s *Server) error {
		s.db = db
		s.rbac = rbac
		return nil
	}
}

func EnableSecureAPI(pk *ecdh.PrivateKey, npk *secp256k1.PrivateKey, licenseKey string) ServerOptions {
	return func(s *Server) error {
		s.secureAPI = true
		s.licenseKey = licenseKey
		if npk == nil {
			key, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				s.log.Error("failed to generate secp256k1 private key")
				return err
			}
			s.npk = key
		} else {
			s.npk = npk
		}
		if pk == nil {
			key, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				s.log.Error("failed to generate private key")
				return err
			}
			s.pk = key
		} else {
			s.pk = pk
		}
		npub := s.npk.PubKey().SerializeUncompressed()
		s.newPublicKey = base64.StdEncoding.EncodeToString(npub[1:])
		s.log.Info("Server New Public Key : " + s.newPublicKey)
		pub := s.pk.PublicKey().Bytes()
		s.publicKey = base64.StdEncoding.EncodeToString(pub)
		s.log.Info("Server Public Key : " + s.publicKey)
		return nil
	}
}

func EnableDebug(allowHeaders string) ServerOptions {
	return func(s *Server) error {
		s.debugMode = true
		s.allowHeaders = allowHeaders
		return nil
	}
}

func SetupSubDirectory(dir string) ServerOptions {
	return func(s *Server) error {
		if !strings.HasPrefix(dir, "/") {
			dir = "/" + dir
		}
		dir = strings.TrimSuffix(dir, "/")
		s.subDirectory = dir
		return nil
	}
}

func SetupServerTimeout(readHeaderTimeoout time.Duration, readTimeout time.Duration, idleTimeout time.Duration) ServerOptions {
	return func(s *Server) error {
		s.s.ReadHeaderTimeout = readHeaderTimeoout
		s.s.ReadTimeout = readTimeout
		s.s.IdleTimeout = idleTimeout
		return nil
	}
}

func SetupTLSServer(clientAuth tls.ClientAuthType, tlsMinVer uint16, tlsCipherSuites []uint16, clientCACertFile string) ServerOptions {
	return func(s *Server) error {
		s.tlsConfig.ClientAuth = clientAuth
		s.tlsConfig.MinVersion = tlsMinVer
		if len(tlsCipherSuites) > 0 {
			// HTTP/2 with TLS 1.2 blacklists several cipher suites.
			// https://tools.ietf.org/html/rfc7540#appendix-A
			//
			// Since the CLI (net/http) automatically uses HTTP/2 with TLS 1.2,
			// we check here if all or some specified cipher suites are blacklisted.
			badCiphers := []string{}
			for _, cipher := range tlsCipherSuites {
				if isbadcipher.IsBadCipher(cipher) {
					// Get the name of the current cipher.
					cipherStr, err := certs.GetCipherName(cipher)
					if err != nil {
						s.log.Error("invalid value for tls_cipher_suites", "err", err)
						return err
					}
					badCiphers = append(badCiphers, cipherStr)
				}
			}
			if len(badCiphers) == len(tlsCipherSuites) {
				s.log.Warn(`WARNING! All cipher suites defined by 'tls_cipher_suites' are blacklisted by the
				HTTP/2 specification. HTTP/2 communication with TLS 1.2 will not work as intended
				and Vault will be unavailable via the CLI.
				Please see https://tools.ietf.org/html/rfc7540#appendix-A for further information.`)
			} else if len(badCiphers) > 0 {
				s.log.Warn(`WARNING! The following cipher suites defined by 'tls_cipher_suites' are
				blacklisted by the HTTP/2 specification,
				Please see https://tools.ietf.org/html/rfc7540#appendix-A for further information.`, "badCiphers", badCiphers)
			}
			s.tlsConfig.CipherSuites = tlsCipherSuites
		}
		if clientCACertFile != "" {
			s.tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			caPool := x509.NewCertPool()
			data, err := os.ReadFile(clientCACertFile)
			if err != nil {
				s.log.Error("failed to read tls_client_ca_file", "err", err)
				return err
			}

			if !caPool.AppendCertsFromPEM(data) {
				s.log.Error("failed to parse CA certificate in tls_client_ca_file", "err", err)
				return err
			}
			s.tlsConfig.ClientCAs = caPool
		}
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
	if os.Getenv("ENSWEB_CERTIFICATE_PASSWORD") != "" {
		cfg.KeyPwd = os.Getenv("ENSWEB_CERTIFICATE_PASSWORD")
	}
	addr := net.JoinHostPort(cfg.Address, cfg.Port)
	hs := &http.Server{
		Addr:              addr,
		IdleTimeout:       DefaultIdleTimeout,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       DefaultReadTimeout,
	}
	s := Server{
		s:         hs,
		cfg:       cfg,
		serverCfg: serverCfg,
		mux:       mux.NewRouter(),
		log:       log.Named("enswebserver"),
		ss:        make(map[string]*SessionStore),
		tlsConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		},
		defaultHeaders: make(map[string]string),
		subDirectory:   "",
	}
	if s.cfg.Secure {
		s.url = "https://" + addr
		if s.cfg.CertFile == "" {
			s.cfg.CertFile = "server.crt"
		}
		if s.cfg.KeyFile == "" {
			s.cfg.KeyFile = "server.key"
		}
		s.log.Info("loading Certificate : " + s.cfg.CertFile)
		if strings.HasSuffix(s.cfg.CertFile, ".pfx") {
			s.log.Info("Loading PFX certificate")
			s.tlsCert = certs.NewTLSCertificateFromPFX(s.cfg.CertFile, s.cfg.KeyPwd)
		} else {
			s.log.Info("Loading PEM certificate")
			s.tlsCert = certs.NewTLSCertificate(s.cfg.CertFile, s.cfg.KeyFile, s.cfg.KeyPwd)
		}
		err := s.tlsCert.Reload()
		if err != nil {
			s.log.Error("failed to load certificate", "err", err)
			return Server{}, err
		}
		s.tlsConfig.GetCertificate = s.tlsCert.GetCertificate
	} else {
		s.url = "http://" + addr
	}
	for _, op := range options {
		err := op(&s)
		if err != nil {
			s.log.Error("failed in setting the option", "err", err)
			return Server{}, err
		}
	}
	if s.secureAPI {
		s.AddRoute(GetPublicKeyAPI, "GET", s.getPublicKeyAPI)
		s.AddRoute(GetPublicKeyAPIV2, "GET", s.getPublicKeyAPIV2)
		s.unProtectedPaths = make([]string, 0)
		s.unProtectedPaths = append(s.unProtectedPaths, s.subDirectory+GetPublicKeyAPI)
		s.unProtectedPaths = append(s.unProtectedPaths, s.subDirectory+GetPublicKeyAPIV2)
	}

	return s, nil
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

// ShowAccount godoc
// @Summary      Get the public key of the server
// @Description  Get the public key of the server
// @Tags         general
// @Accept       json
// @Produce      json
// @Success      200 {object}  PublicKeyResponse
// @Router       /api/v2/getpublickey [get]
func (s *Server) getPublicKeyAPIV2(req *Request) *Result {
	pr := PublicKeyResponse{
		BaseResponse: BaseResponse{
			Status: true,
		},
		PublicKey: s.newPublicKey,
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

func (s *Server) SetDefaultHeaders(headers map[string]string) {
	for k, v := range headers {
		s.defaultHeaders[k] = v
	}
}

func (s *Server) isUnProtectedPath(path string) bool {
	if s.secureAPI {
		if s.unProtectedPaths == nil {
			return false
		}
		for _, p := range s.unProtectedPaths {
			if p == path {
				return true
			}
		}
		return false
	} else {
		return true
	}
}

func (s *Server) AddUnProtectedPath(path string) {
	if s.secureAPI {
		if s.unProtectedPaths == nil {
			s.unProtectedPaths = make([]string, 0)
		}
		path = s.subDirectory + path
		s.unProtectedPaths = append(s.unProtectedPaths, path)
	}
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
		if s.tlsConfig != nil {
			ln = tls.NewListener(ln, s.tlsConfig)
			go s.s.Serve(ln)
		} else {
			go s.s.ServeTLS(ln, s.cfg.CertFile, s.cfg.KeyFile)
		}
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
