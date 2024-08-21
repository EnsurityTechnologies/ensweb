package ensweb

type Config struct {
	Address     string `json:"address"`
	Port        string `json:"port"`
	Secure      bool   `json:"secure"`
	CertFile    string `json:"cert_file"`
	KeyFile     string `json:"key_file"`
	KeyPwd      string `json:"key_pwd"`
	Secret      string `json:"secret"`
	EnableProxy bool   `json:"enable_proxy"`
	ProxyUrl    string `json:"proxy_url"`
}
