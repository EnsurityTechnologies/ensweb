package ensweb

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/EnsurityTechnologies/config"
	"github.com/EnsurityTechnologies/helper/jsonutil"
	"github.com/EnsurityTechnologies/logger"
	"github.com/EnsurityTechnologies/uuid"
)

// Client : Client struct
type Client struct {
	config          *config.Config
	log             logger.Logger
	address         string
	addr            *url.URL
	hc              *http.Client
	th              TokenHelper
	defaultTimeout  time.Duration
	token           string
	cookies         []*http.Cookie
	secureAPI       bool
	pk              *ecdh.PrivateKey
	publicKey       string
	licenseKey      string
	serverPublicKey string
	ss              string
	jid             string
}

type ClientOptions = func(*Client) error

func SetClientDefaultTimeout(timeout time.Duration) ClientOptions {
	return func(c *Client) error {
		c.defaultTimeout = timeout
		return nil
	}
}

func SetClientTokenHelper(filename string) ClientOptions {
	return func(c *Client) error {
		th, err := NewInternalTokenHelper(filename)
		if err != nil {
			return err
		}
		c.th = th
		return nil
	}
}

func EnableClientSecureAPI(licenseKey string) ClientOptions {
	return func(c *Client) error {
		c.secureAPI = true
		c.licenseKey = licenseKey
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			c.log.Error("failed to generate private key", "err", err)
			return err
		}
		c.pk = key
		pub := c.pk.PublicKey().Bytes()
		c.publicKey = base64.StdEncoding.EncodeToString(pub)
		c.log.Info("Public key : " + c.publicKey)
		req, err := c.JSONRequest("GET", GetPublicKeyAPI, nil)
		if err != nil {
			c.log.Error("failed to create json request", "err", err)
			return err
		}
		resp, err := c.Do(req)
		if err != nil {
			c.log.Error("failed to get server public key, failed to get response", "err", err)
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			c.log.Error("failed to get server public key, no response from server")
			return fmt.Errorf("failed to get server public key, no response from server")
		}
		var pr PublicKeyResponse
		err = jsonutil.DecodeJSONFromReader(resp.Body, &pr)
		if err != nil {
			c.log.Error("failed to get server public key, json unmarshell failed", "err", err)
			return err
		}
		c.serverPublicKey = pr.PublicKey
		err = c.getSharedSecret()
		if err != nil {
			c.log.Error("failed to generate shared secret", "err", err)
			return err
		}
		return nil
	}
}

// NewClient : Create new client handle
func NewClient(config *config.Config, log logger.Logger, options ...ClientOptions) (Client, error) {
	var address string
	var tr *http.Transport
	clog := log.Named("enswebclient")
	if config.Production == "true" {
		address = fmt.Sprintf("https://%s", net.JoinHostPort(config.ServerAddress, config.ServerPort))
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		address = fmt.Sprintf("http://%s", net.JoinHostPort(config.ServerAddress, config.ServerPort))
		tr = &http.Transport{
			IdleConnTimeout: 30 * time.Second,
		}
	}

	hc := &http.Client{
		Transport: tr,
		Timeout:   DefaultTimeout,
	}

	addr, err := url.Parse(address)

	if err != nil {
		clog.Error("failed to parse server address", "err", err)
		return Client{}, err
	}

	c := Client{
		config:  config,
		log:     clog,
		address: address,
		addr:    addr,
		hc:      hc,
		jid:     uuid.New().String(),
	}

	for _, op := range options {
		err = op(&c)
		if err != nil {
			clog.Error("failed in setting the option", "err", err)
			return Client{}, err
		}
	}

	return c, nil
}

func (c *Client) JSONRequest(method string, requestPath string, model interface{}) (*http.Request, error) {
	var body *bytes.Buffer
	if model != nil {
		j, err := json.Marshal(model)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(j)
	} else {
		body = bytes.NewBuffer(make([]byte, 0))
	}
	url := &url.URL{
		Scheme: c.addr.Scheme,
		Host:   c.addr.Host,
		User:   c.addr.User,
		Path:   path.Join(c.addr.Path, requestPath),
	}
	req, err := http.NewRequest(method, url.RequestURI(), body)
	req.Host = url.Host
	req.URL.User = url.User
	req.URL.Scheme = url.Scheme
	req.URL.Host = url.Host
	req.Header.Set("Content-Type", "application/json")
	return req, err
}

func (c *Client) MultiFormRequest(method string, requestPath string, field map[string]string, files map[string]string) (*http.Request, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range field {
		fw, err := w.CreateFormField(k)
		if err != nil {
			return nil, err
		}
		if _, err = io.Copy(fw, strings.NewReader(v)); err != nil {
			return nil, err
		}
	}
	for k, v := range files {
		fw, err := w.CreateFormFile(k, filepath.Base(v))
		if err != nil {
			return nil, err
		}
		f, err := os.Open(v)
		if err != nil {
			return nil, err
		}
		if _, err = io.Copy(fw, f); err != nil {
			return nil, err
		}
	}
	err := w.Close()
	if err != nil {
		return nil, err
	}

	url := &url.URL{
		Scheme: c.addr.Scheme,
		Host:   c.addr.Host,
		User:   c.addr.User,
		Path:   path.Join(c.addr.Path, requestPath),
	}
	req, err := http.NewRequest(method, url.RequestURI(), &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Host = url.Host
	req.URL.User = url.User
	req.URL.Scheme = url.Scheme
	req.URL.Host = url.Host
	return req, err
}

func (c *Client) SetAuthorization(req *http.Request, token string) {
	var bearer = "Bearer " + token
	req.Header.Set("Authorization", bearer)
}

func (c *Client) Do(req *http.Request, timeout ...time.Duration) (*http.Response, error) {
	if timeout != nil {
		c.hc.Timeout = timeout[0]
	} else {
		c.hc.Timeout = c.defaultTimeout
	}
	return c.hc.Do(req)
}

func (c *Client) SetCookies(cookies []*http.Cookie) {
	c.cookies = cookies
}

func (c *Client) GetCookies() []*http.Cookie {
	return c.cookies
}

func (c *Client) SetToken(token string) error {
	if c.th != nil {
		return c.th.Store(token)
	}
	c.token = token
	return nil
}

func (c *Client) GetToken() string {
	if c.th != nil {
		tk, err := c.th.Get()
		if err != nil {
			return "InvalidToken"
		} else {
			return tk
		}
	}
	return c.token
}

func (c *Client) ParseMutilform(resp *http.Response, dirPath string) ([]string, map[string]string, error) {
	mediatype, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, err
	}
	if mediatype != "multipart/form-data" {
		return nil, nil, fmt.Errorf("invalid content type %s", mediatype)
	}
	defer resp.Body.Close()
	mr := multipart.NewReader(resp.Body, params["boundary"])

	paramFiles := make([]string, 0)
	paramTexts := make(map[string]string)
	for {
		part, err := mr.NextPart()
		if err != nil {
			if err != io.EOF { //io.EOF error means reading is complete
				return paramFiles, paramTexts, fmt.Errorf(" error reading multipart request: %+v", err)
			}
			break
		}
		if part.FileName() != "" {
			f, err := os.Create(dirPath + part.FileName())
			if err != nil {
				return paramFiles, paramTexts, fmt.Errorf("error in creating file %+v", err)
			}
			value, _ := ioutil.ReadAll(part)
			f.Write(value)
			f.Close()
			if err != nil {
				return paramFiles, paramTexts, fmt.Errorf("error reading file param %+v", err)
			}
			paramFiles = append(paramFiles, dirPath+part.FileName())
		} else {
			name := part.FormName()
			buf := new(bytes.Buffer)
			buf.ReadFrom(part)
			paramTexts[name] = buf.String()
		}
	}
	return paramFiles, paramTexts, nil
}

func (c *Client) getSharedSecret() error {
	if c.ss != "" {
		return nil
	}
	pb, err := base64.StdEncoding.DecodeString(c.serverPublicKey)
	if err != nil {
		c.log.Error("invalid pubkey, failed to decode base 64 string", "err", err)
		return err
	}
	pub, err := ecdh.P256().NewPublicKey(pb)
	if err != nil {
		c.log.Error("invalid pubkey, failed to frame pubkey", "err", err)
		return err
	}
	kb, err := c.pk.ECDH(pub)
	if err != nil {
		c.log.Error("failed to create shared secret", "err", err)
		return err
	}
	ss := sha256.Sum256(kb)
	c.ss = hex.EncodeToString(ss[:])
	return nil
}

func (c *Client) SendJSON(method string, path string, auth bool, headers map[string]string, in interface{}, out interface{}, errout interface{}, timeout ...time.Duration) error {
	var req *http.Request
	var err error
	if c.secureAPI {
		var sd SecureData
		if in != nil {
			sd.Data, err = encryptModel(c.ss, in)
			if err != nil {
				c.log.Error("failed to encrypt input model", "err", err)
				return err
			}
			req, err = c.JSONRequest(method, path, sd)
		} else {
			req, err = c.JSONRequest(method, path, nil)
		}
		if err != nil {
			c.log.Error("failed to create json request", "err", err)
			return err
		}
		reqID := RequestID{
			ID:        uuid.New().String(),
			JourneyID: c.jid,
			TS:        time.Now().Unix(),
			AppID:     "goclient",
		}

		rid, err := encryptModel(c.ss, reqID)
		if err != nil {
			c.log.Error("failed to encrypt request model", "err", err)
			return err
		}
		req.Header.Add(RequestIDHdr, rid)
		req.Header.Add(LicenseKeyHdr, c.licenseKey)
		req.Header.Add(PublicKeyHdr, c.publicKey)
	} else {
		req, err = c.JSONRequest(method, path, in)
		if err != nil {
			c.log.Error("failed to create json request", "err", err)
			return err
		}
	}

	if auth {
		c.SetAuthorization(req, c.GetToken())
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req, timeout...)
	if err != nil {
		c.log.Error("failed to get response from the server", "err", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode == http.StatusOK || errout == nil {
		if c.secureAPI {
			var sd SecureData
			err = jsonutil.DecodeJSONFromReader(resp.Body, &sd)
			if err != nil {
				c.log.Error("failed to parse json output", "err", err)
				return err
			}
			err = decryptModel(c.ss, sd.Data, out)
			if err != nil {
				c.log.Error("failed to decrypt model", "err", err)
				return err
			}
		} else {
			err = jsonutil.DecodeJSONFromReader(resp.Body, out)
			if err != nil {
				c.log.Error("failed to parse json output", "err", err)
				return err
			}
		}
	} else {
		err = jsonutil.DecodeJSONFromReader(resp.Body, errout)
		if err != nil {
			c.log.Error("failed to parse json output", "err", err)
			return err
		}
	}
	if resp.StatusCode != http.StatusOK {
		str := fmt.Sprintf("request failed with status : %d", resp.StatusCode)
		c.log.Error(str)
		return fmt.Errorf(str)
	}
	return nil

}
