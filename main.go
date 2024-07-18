package main

import (
	"fmt"
	"log"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func main() {
	client, err := wgctrl.New()
	if err != nil {
		log.Fatalf("failed to initialize wgctrl: %v", err)
	}

	devices, err := client.Devices()
	if err != nil {
		log.Fatalf("failed to get devices: %v", err)
	}

	fmt.Printf("found %d devices\n", len(devices))
	for i, device := range devices {
		fmt.Printf("device %v: %s\n", i, device.Name)
	}
}
