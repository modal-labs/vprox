package lib

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// AwsInterface contains information about a network interface.
type AwsInterface struct {
	MacAddress  string
	InterfaceId string // eni-[XXXXXXXXXX]
	PrivateIps  []string
}

// AwsMetadata is a client for the AWS instance metadata service.
type AwsMetadata struct {
	client *imds.Client
}

// NewAwsMetadata creates a new AWS metadata client.
func NewAwsMetadata() *AwsMetadata {
	return &AwsMetadata{
		client: imds.New(imds.Options{}),
	}
}

// GetAddresses returns the info about the instance's network interfaces.
func (am *AwsMetadata) GetAddresses() ([]AwsInterface, error) {
	prefix := "network/interfaces/macs"
	result, err := am.get(prefix)
	if err != nil {
		return nil, err
	}

	interfaces := []AwsInterface{}
	macs := strings.Split(result, "\n")
	for _, mac := range macs {
		mac = strings.TrimRight(mac, "/")

		interfaceId, err := am.get(fmt.Sprintf("%s/%s/interface-id", prefix, mac))
		if err != nil {
			return nil, err
		}

		result, err := am.get(fmt.Sprintf("%s/%s/local-ipv4s", prefix, mac))
		if err != nil {
			return nil, fmt.Errorf("failed to get private IPs for MAC %s: %v", mac, err)
		}
		privateIps := strings.Split(result, "\n")

		interfaces = append(interfaces, AwsInterface{
			MacAddress:  mac,
			InterfaceId: interfaceId,
			PrivateIps:  privateIps,
		})
	}

	return interfaces, nil
}

func (am *AwsMetadata) get(path string) (string, error) {
	output, err := am.client.GetMetadata(context.Background(), &imds.GetMetadataInput{
		Path: path,
	})
	if err != nil {
		return "", err
	}

	buf, err := io.ReadAll(output.Content)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}
