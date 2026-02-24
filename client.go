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

	"github.com/EnsurityTechnologies/helper/jsonutil"
	"github.com/EnsurityTechnologies/logger"
	"github.com/EnsurityTechnologies/uuid"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type AuthenticateFunc func() error

// Client : Client struct
type Client struct {
	cfg             *Config
	log             logger.Logger
	address         string
	addr            *url.URL
	hc              *http.Client
	th              TokenHelper
	defaultTimeout  time.Duration
	token           string
	rtoken          string
	cookies         []*http.Cookie
	secureAPI       bool
	pk              *ecdh.PrivateKey
	npk             *secp256k1.PrivateKey
	publicKey       string
	licenseKey      string
	serverPublicKey string
	ss              string
	nss             []byte
	jid             string
	subDirectory    string
}

type ClientOptions = func(*Client) error

func SetClientDefaultTimeout(timeout time.Duration) ClientOptions {
	return func(c *Client) error {
		c.defaultTimeout = timeout
		return nil
	}
}

func SetClientTokenHelper(th TokenHelper) ClientOptions {
	return func(c *Client) error {
		c.th = th
		return nil
	}
}

func EnableClientSecureAPI(licenseKey string, enableV2 bool) ClientOptions {
	return func(c *Client) error {
		c.secureAPI = true
		c.licenseKey = licenseKey
		if enableV2 {
			nkey, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				c.log.Error("failed to generate secp256k1 private key")
				return err
			}
			c.npk = nkey
			npub := c.npk.PubKey().SerializeUncompressed()
			c.publicKey = base64.StdEncoding.EncodeToString(npub[1:])
			req, err := c.JSONRequest("GET", c.subDirectory+GetPublicKeyAPIV2, nil)
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
			if resp.StatusCode != http.StatusOK {
				c.log.Error("failed to get server public key, invalid status code", "statuscode", resp.StatusCode)
				if resp.Body != nil {
					body, _ := ioutil.ReadAll(resp.Body)
					c.log.Error("response body", "body", string(body))
				}
				return fmt.Errorf("failed to get server public key, invalid status code: %d", resp.StatusCode)
			}
			var pr PublicKeyResponse
			err = jsonutil.DecodeJSONFromReader(resp.Body, &pr)
			if err != nil {
				c.log.Error("failed to get server public key, json unmarshell failed", "err", err)
				return err
			}
			c.serverPublicKey = pr.PublicKey
		} else {
			key, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				c.log.Error("failed to generate private key", "err", err)
				return err
			}
			c.pk = key
			pub := c.pk.PublicKey().Bytes()
			c.publicKey = base64.StdEncoding.EncodeToString(pub)
			req, err := c.JSONRequest("GET", c.subDirectory+GetPublicKeyAPI, nil)
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
			if resp.StatusCode != http.StatusOK {
				c.log.Error("failed to get server public key, invalid status code", "statuscode", resp.StatusCode)
				if resp.Body != nil {
					body, _ := ioutil.ReadAll(resp.Body)
					c.log.Error("response body", "body", string(body))
				}
				return fmt.Errorf("failed to get server public key, invalid status code: %d", resp.StatusCode)
			}
			var pr PublicKeyResponse
			err = jsonutil.DecodeJSONFromReader(resp.Body, &pr)
			if err != nil {
				c.log.Error("failed to get server public key, json unmarshell failed", "err", err)
				return err
			}
			c.serverPublicKey = pr.PublicKey
		}
		err := c.getSharedSecret()
		if err != nil {
			c.log.Error("failed to generate shared secret", "err", err)
			return err
		}
		return nil
	}
}

// NewClient : Create new client handle
func NewClient(cfg *Config, log logger.Logger, options ...ClientOptions) (Client, error) {
	var address string
	var tr *http.Transport
	clog := log.Named("enswebclient")
	if cfg.Secure {
		address = fmt.Sprintf("https://%s", net.JoinHostPort(cfg.Address, cfg.Port))
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		address = fmt.Sprintf("http://%s", net.JoinHostPort(cfg.Address, cfg.Port))
		tr = &http.Transport{
			IdleConnTimeout: 30 * time.Second,
		}
	}
	if cfg.EnableProxy {
		url, err := url.Parse(cfg.ProxyUrl)
		if err != nil {
			log.Error("failed to create client, failed parse proxy url", "err", err)
			return Client{}, err
		}
		tr.Proxy = http.ProxyURL(url)
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
		cfg:          cfg,
		log:          clog,
		address:      address,
		addr:         addr,
		hc:           hc,
		jid:          uuid.New().String(),
		subDirectory: cfg.SubDirectory,
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

func (c *Client) SetUrl(siteUrl string) error {
	var tr *http.Transport
	if strings.Contains(siteUrl, "https") {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		tr = &http.Transport{
			IdleConnTimeout: 30 * time.Second,
		}
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   DefaultTimeout,
	}
	addr, err := url.Parse(siteUrl)
	if err != nil {
		c.log.Error("failed to parse server address", "err", err)
		return err
	}
	c.addr = addr
	c.hc = hc
	c.address = siteUrl
	return nil
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
		return c.th.StoreAccessToken(token)
	}
	c.token = token
	return nil
}

func (c *Client) SetRefreshToken(token string) error {
	if c.th != nil {
		return c.th.StoreRefreshToken(token)
	}
	c.rtoken = token
	return nil
}

func (c *Client) GetToken() string {
	if c.th != nil {
		tk, err := c.th.GetAccessToken()
		if err != nil {
			return "InvalidToken"
		} else {
			return tk
		}
	}
	return c.token
}

func (c *Client) GetRefreshToken() string {
	if c.th != nil {
		tk, err := c.th.GetRefreshToken()
		if err != nil {
			return "InvalidToken"
		} else {
			return tk
		}
	}
	return c.rtoken
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
	if c.nss != nil {
		return nil
	}
	if c.ss != "" {
		return nil
	}
	pb, err := base64.StdEncoding.DecodeString(c.serverPublicKey)
	if err != nil {
		c.log.Error("invalid pubkey, failed to decode base 64 string", "err", err)
		return err
	}

	tot := make([]byte, len(pb)+1)
	tot[0] = 0x04
	copy(tot[1:], pb)
	pk, err := secp256k1.ParsePubKey(tot)
	if err == nil {
		c.nss = secp256k1.GenerateSharedSecret(c.npk, pk)
		return nil
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

func (c *Client) sendJSON(method string, path string, auth bool, querry map[string]string, headers map[string]string, in interface{}, out interface{}, errout interface{}, timeout ...time.Duration) (int, error) {
	var req *http.Request
	var err error
	if c.secureAPI {
		var sd SecureData
		if in != nil {
			sd.Data, err = encryptModel(c.nss, c.ss, in)
			if err != nil {
				c.log.Error("failed to encrypt input model", "err", err)
				return 0, err
			}
			req, err = c.JSONRequest(method, path, sd)
		} else {
			req, err = c.JSONRequest(method, path, nil)
		}
		if err != nil {
			c.log.Error("failed to create json request", "err", err)
			return 0, err
		}
		reqID := RequestID{
			ID:        uuid.New().String(),
			JourneyID: c.jid,
			TS:        time.Now().Unix(),
			AppID:     "goclient",
		}

		rid, err := encryptModel(c.nss, c.ss, reqID)
		if err != nil {
			c.log.Error("failed to encrypt request model", "err", err)
			return 0, err
		}
		req.Header.Add(RequestIDHdr, rid)
		req.Header.Add(LicenseKeyHdr, c.licenseKey)
		req.Header.Add(PublicKeyHdr, c.publicKey)
	} else {
		req, err = c.JSONRequest(method, path, in)
		if err != nil {
			c.log.Error("failed to create json request", "err", err)
			return 0, err
		}
	}

	if auth {
		c.SetAuthorization(req, c.GetToken())
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if querry != nil {
		q := req.URL.Query()
		for k, v := range querry {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}
	resp, err := c.Do(req, timeout...)
	if err != nil {
		c.log.Error("failed to get response from the server", "err", err)
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusOK || errout == nil {
		if c.secureAPI {
			var sd SecureData
			err = jsonutil.DecodeJSONFromReader(resp.Body, &sd)
			if err != nil {
				c.log.Error("failed to parse json output", "err", err)
				return resp.StatusCode, err
			}
			err = decryptModel(c.nss, c.ss, sd.Data, out)
			if err != nil {
				c.log.Error("failed to decrypt model", "err", err)
				return resp.StatusCode, err
			}
		} else {
			err = jsonutil.DecodeJSONFromReader(resp.Body, out)
			if err != nil {
				c.log.Error("failed to parse json output", "err", err, "statuscode", resp.StatusCode)
				return resp.StatusCode, err
			}
		}
	} else {
		err = jsonutil.DecodeJSONFromReader(resp.Body, errout)
		if err != nil {
			c.log.Error("failed to parse json output", "err", err, "statuscode", resp.StatusCode)
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil

}

func (c *Client) SendJSON(method string, path string, auth bool, querry map[string]string, headers map[string]string, in interface{}, out interface{}, errout interface{}, af AuthenticateFunc, timeout ...time.Duration) error {
	path = c.subDirectory + path
	statusCode, err := c.sendJSON(method, path, auth, querry, headers, in, out, errout, timeout...)
	if statusCode == http.StatusUnauthorized {
		c.log.Debug("unauthorized calling authenticate function")
		if af != nil {
			c.log.Debug("Calling authenticate function")
			err = af()
			if err == nil {
				_, err = c.sendJSON(method, path, auth, querry, headers, in, out, errout, timeout...)
				if err != nil {
					return err
				}
			}
		}
	}
	if err != nil {
		return err
	}

	return nil
}
