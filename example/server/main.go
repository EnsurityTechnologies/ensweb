package main

import (
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/EnsurityTechnologies/config"
	_ "github.com/EnsurityTechnologies/ensweb/example/server/docs"
	"github.com/EnsurityTechnologies/logger"
)

func main() {
	var licenseKey string
	flag.StringVar(&licenseKey, "l", "", "License key")
	flag.Parse()
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		panic(err)
	}
	fp, err := os.OpenFile(cfg.LogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	logOptions := &logger.LoggerOptions{
		Name:   "Main",
		Color:  []logger.ColorOption{logger.AutoColor, logger.ColorOff},
		Output: []io.Writer{logger.DefaultOutput, fp},
	}

	log := logger.New(logOptions)
	s, err := NewServer(cfg, log, licenseKey)
	if err != nil {
		log.Error("Failed to create server")
		return
	}
	log.Info("Starting server...")
	go s.Start()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, syscall.SIGINT)

	<-c
	s.Shutdown()
	log.Info("Shutting down...")
}
