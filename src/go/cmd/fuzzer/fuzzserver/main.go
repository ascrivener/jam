package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"jam/pkg/fuzzinterface"
	"jam/pkg/staterepository"
)

func main() {
	// Parse command line arguments
	socketPath := flag.String("socket", "/tmp/jam_target.sock", "Path for the Unix domain socket")
	dataDir := flag.String("datadir", "./data", "Path to the data directory")
	flag.Parse()

	log.Printf("JAM Fuzzer Interface Server")
	log.Printf("Socket path: %s", *socketPath)
	log.Printf("Data directory: %s", *dataDir)

	// Ensure the data directory exists
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	err := staterepository.InitializeGlobalRepository(*dataDir + "/state")
	if err != nil {
		log.Fatalf("Failed to initialize global state repository: %v", err)
	}
	defer staterepository.CloseGlobalRepository()
	// Create and start the server
	server := fuzzinterface.NewServer()
	if err := server.Start(*socketPath); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Wait for termination signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-signalChan
	log.Printf("Received signal %v, shutting down", sig)
}
