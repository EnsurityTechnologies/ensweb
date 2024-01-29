package main

import "github.com/EnsurityTechnologies/ensweb"

type Request struct {
	UserName string `json:"email"`
	Password string `json:"password"`
}

type Response struct {
	ensweb.BaseResponse
	Token string `json:"Token"`
}
