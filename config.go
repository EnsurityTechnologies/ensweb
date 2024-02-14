package ensweb

type Config struct {
	Address  string `json:"address"`
	Port     string `json:"port"`
	Secure   bool   `json:"secure"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	Secret   string `json:"secret"`
}
