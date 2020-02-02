package cache

import (
	"context"
	"net/http"

	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/rpc/layer"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

type RemoteCache struct {
	client layer.Layer
}

type RemoteURL string

func NewRemoteCache(url RemoteURL) cache.LayerCache {
	client := layer.NewLayerProtobufClient(string(url), &http.Client{})
	return &RemoteCache{client: client}
}

func (c RemoteCache) PutLayer(layerID string, layerInfo types.LayerInfo) error {
	_, err := c.client.Put(context.Background(), rpc.ConvertToRpcLayerInfo(layerID, layerInfo))
	if err != nil {
		return err
	}
	return nil
}

func (c RemoteCache) MissingLayers(layerIDs []string) ([]string, error) {
	layers, err := c.client.MissingLayers(context.Background(), rpc.ConvertToRpcLayers(layerIDs))
	if err != nil {
		return nil, err
	}
	return layers.LayerIds, nil
}
