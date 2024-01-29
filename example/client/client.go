package main

import (
	"fmt"

	"github.com/EnsurityTechnologies/config"
	"github.com/EnsurityTechnologies/ensweb"
	"github.com/EnsurityTechnologies/logger"
)

// route declaration
const (
	LoginRoute        string = "/api/login"
	LoginSessionRoute string = "/api/home"
)

type Client struct {
	ensweb.Client
	log logger.Logger
}

func NewClient(cfg *config.Config, log logger.Logger, licenseKey string) (*Client, error) {
	c := &Client{log: log.Named("client")}
	var err error
	// th, err := ensweb.NewInternalTokenHelper("token.txt")
	// if err != nil {
	// 	return nil, err
	// }
	if licenseKey == "" {
		c.Client, err = ensweb.NewClient(cfg, log, ensweb.SetClientTokenHelper("token.txt"))
	} else {
		c.Client, err = ensweb.NewClient(cfg, log, ensweb.SetClientTokenHelper("token.txt"), ensweb.EnableClientSecureAPI(licenseKey))
	}

	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) Login(userName string, password string) error {
	req := Request{
		UserName: userName,
		Password: password,
	}

	var resp Response

	err := c.SendJSON("POST", LoginRoute, false, nil, req, &resp, nil)

	if err != nil {
		c.log.Error("failed to login", "err", err, "msg", resp.Message)
		return err
	}

	if !resp.Status {
		c.log.Error("failed to login, " + resp.Message)
		return fmt.Errorf(resp.Message)
	} else {
		c.log.Info("User logged in successfully")
		c.SetToken(resp.Token)
	}
	return nil
}

func (c *Client) LoginSession() (string, error) {
	var resp Response
	err := c.SendJSON("GET", LoginSessionRoute, true, nil, nil, &resp, nil)
	if err != nil {
		c.log.Error("failed to get login session", "err", err, "msg", resp.Message)
		return "", err
	}
	if !resp.Status {
		c.log.Error("failed to get login session, " + resp.Message)
		return "", fmt.Errorf(resp.Message)
	}
	return resp.Message, nil
}
