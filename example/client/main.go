package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/EnsurityTechnologies/config"
	"github.com/EnsurityTechnologies/logger"
)

func main() {
	var userName string
	var password string
	var licenseKey string
	flag.StringVar(&userName, "u", "", "User Name")
	flag.StringVar(&password, "p", "", "Password")
	flag.StringVar(&licenseKey, "l", "", "License key")

	logOptions := &logger.LoggerOptions{
		Name:   "ClientExample",
		Color:  []logger.ColorOption{logger.AutoColor},
		Output: []io.Writer{logger.DefaultOutput},
	}

	log := logger.New(logOptions)

	log.Info("Starting Client...")

	if len(os.Args) < 2 {
		log.Error("Invalid Command")
		return
	}
	cfg, err := config.LoadConfig("config.json")

	if err != nil {
		fmt.Printf("%s\n", err.Error())
		log.Error("Invalid Config file")
		return
	}

	cmd := os.Args[1]
	os.Args = os.Args[1:]
	flag.Parse()
	c, err := NewClient(cfg, log, licenseKey)
	if err != nil {
		log.Error(err.Error())
		return
	}
	switch cmd {
	case "Login":
		err = c.Login(userName, password)
		if err != nil {
			log.Error(err.Error())
			return
		}
		log.Info("Login successfully completed")
	case "LoginSession":
		msg, err := c.LoginSession()
		if err != nil {
			log.Error(err.Error())
		} else {
			log.Info(msg)
		}
	default:
		log.Error("Invalid command")
	}
}
