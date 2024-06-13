package ensweb

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func (s *Server) BasicAuthHandle(claims jwt.Claims, hf HandlerFunc, af AuthFunc, ef HandlerFunc) HandlerFunc {
	return HandlerFunc(func(req *Request) *Result {
		err := s.ValidateJWTToken(req.ClientToken.Token, claims)
		if err != nil {
			if ef != nil {
				return ef(req)
			} else {
				return s.RenderJSONError(req, http.StatusUnauthorized, err.Error(), err.Error())
			}
		}
		req.ClientToken.Model = claims
		req.ClientToken.Verified = true
		if af != nil {
			if !af(req) {
				if ef != nil {
					return ef(req)
				} else {
					return s.RenderJSONError(req, http.StatusUnauthorized, "Access denined", "Access denied")
				}
			}
		}
		return hf(req)
	})
}

func (s *Server) APIKeyAuthHandle(hf HandlerFunc, ef HandlerFunc) HandlerFunc {
	return HandlerFunc(func(req *Request) *Result {
		if s.apiKey != s.GetReqHeader(req, APIKeyHeader) {
			if ef != nil {
				return ef(req)
			} else {
				return s.RenderJSONError(req, http.StatusUnauthorized, "API Key is not matched", "API Key is not matched")
			}
		}
		req.ClientToken.APIKeyVerified = true
		return hf(req)
	})
}

func (s *Server) SessionAuthHandle(claims jwt.Claims, sessionName string, sessionKey string, hf HandlerFunc, ef HandlerFunc) HandlerFunc {
	return HandlerFunc(func(req *Request) *Result {

		token := s.GetSessionCookies(req, sessionName, sessionKey)
		if token == nil {
			if ef != nil {
				return ef(req)
			} else {
				return s.RenderJSONError(req, http.StatusUnauthorized, "invalid session", "invalid session")
			}
		}
		err := s.ValidateJWTToken(token.(string), claims)
		if err != nil {
			if ef != nil {
				return ef(req)
			} else {
				return s.RenderJSONError(req, http.StatusUnauthorized, err.Error(), err.Error())
			}
		}
		req.ClientToken.Model = claims
		req.ClientToken.Verified = true
		return hf(req)
	})
}
