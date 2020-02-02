// +build wireinject

package client

import (
	"context"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/google/wire"
)

func initializeScanner(ctx context.Context, imageName string, layerCache cache.LayerCache, customHeaders client.CustomHeaders,
	url client.RemoteURL) (scanner.Scanner, error) {
	wire.Build(scanner.ClientSet)
	return scanner.Scanner{}, nil
}

func initializeVulnerabilityClient() vulnerability.Client {
	wire.Build(vulnerability.SuperSet)
	return vulnerability.Client{}
}
