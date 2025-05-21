package net

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"time"
)

// This is an example of how to use the JAMNP-S client
// Note: This is not a runnable test as it requires a real polkajam node to connect to
func Example_jamnpsClient() {
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create client configuration
	config := Config{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		ChainHash:  "abcd1234", // Replace with actual chain genesis hash
		Version:    "0",
		IsBuilder:  false,
	}

	// Create client
	client, err := NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Connect to a polkajam node
	// Replace with your Docker container's address
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := client.Connect(ctx, "localhost:31234")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Example: Request a work report
	// You need a valid work report hash
	var reportHash [32]byte
	// Fill reportHash with a real hash value

	workReport, err := RequestWorkReport(ctx, client, session, reportHash)
	if err != nil {
		log.Printf("Failed to get work report: %v", err)
	} else {
		log.Printf("Got work report of size %d bytes", len(workReport))
	}

	// Example: Set up a block announcement handler
	handler := &exampleBlockHandler{}
	blockHandler, err := NewBlockHandler(client, session, handler)
	if err != nil {
		log.Fatalf("Failed to create block handler: %v", err)
	}

	err = blockHandler.Start(context.Background())
	if err != nil {
		log.Fatalf("Failed to start block handler: %v", err)
	}

	// The block handler will now handle incoming block announcements
	// and call handler.HandleBlockAnnouncement for each one

	// Keep the connection alive for a while to receive announcements
	time.Sleep(60 * time.Second)
}

// exampleBlockHandler implements the BlockAnnouncementHandler interface
type exampleBlockHandler struct{}

func (h *exampleBlockHandler) HandleBlockAnnouncement(header []byte) error {
	fmt.Printf("Received block announcement: %d bytes\n", len(header))
	return nil
}

// This example shows how to submit a work package
func Example_submitWorkPackage() {
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create client configuration for a builder
	config := Config{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		ChainHash:  "abcd1234", // Replace with actual chain genesis hash
		Version:    "0",
		IsBuilder:  true, // Identify as a builder
	}

	// Create client
	client, err := NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Connect to a guarantor node
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := client.Connect(ctx, "guarantor-node:31234")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Create a work package (this would be created according to your application needs)
	workPackage := []byte("example work package")

	// Submit the work package
	err = SubmitWorkPackage(ctx, client, session, workPackage)
	if err != nil {
		log.Fatalf("Failed to submit work package: %v", err)
	}

	log.Println("Work package submitted successfully")
}
