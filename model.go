package ensweb

type BaseResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

type PublicKeyResponse struct {
	BaseResponse
	PublicKey string `json:"publicKey"`
}

type RequestID struct {
	ID        string `json:"uuid"`
	JourneyID string `json:"journeyId"`
	TS        int64  `json:"ts"`
	AppID     string `json:"appid"`
}
