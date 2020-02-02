package server

import (
	"context"
	"testing"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/trivy/rpc/common"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/cache"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	rpcLayer "github.com/aquasecurity/trivy/rpc/layer"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

func TestLayerServer_Put(t *testing.T) {
	type args struct {
		in *rpcLayer.PutRequest
	}
	tests := []struct {
		name     string
		args     args
		putLayer cache.PutLayerExpectation
		want     *google_protobuf.Empty
		wantErr  string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcLayer.PutRequest{
					LayerId:             "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
					DecompressedLayerId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					SchemaVersion:       1,
					Os: &common.OS{
						Family: "alpine",
						Name:   "3.11",
					},
					PackageInfos: []*common.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []*common.Package{
								{
									Name:       "binary",
									Version:    "1.2.3",
									Release:    "1",
									Epoch:      2,
									Arch:       "x86_64",
									SrcName:    "src",
									SrcVersion: "1.2.3",
									SrcRelease: "1",
									SrcEpoch:   2,
								},
								{
									Name:       "vim-minimal",
									Version:    "7.4.160",
									Release:    "5.el7",
									Epoch:      2,
									Arch:       "x86_64",
									SrcName:    "vim",
									SrcVersion: "7.4.160",
									SrcRelease: "5.el7",
									SrcEpoch:   2,
								},
							},
						},
					},
					Applications: []*common.Application{
						{
							Type:     "composer",
							FilePath: "php-app/composer.lock",
							Libraries: []*common.Library{
								{
									Name:    "guzzlehttp/guzzle",
									Version: "6.2.0",
								},
								{
									Name:    "guzzlehttp/promises",
									Version: "v1.3.1",
								},
							},
						},
					},
					OpaqueDirs:    []string{"etc/"},
					WhiteoutFiles: []string{"etc/hostname"},
				},
			},
			putLayer: cache.PutLayerExpectation{
				Args: cache.PutLayerArgs{
					LayerID:             "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
					DecompressedLayerID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					LayerInfo: types.LayerInfo{
						SchemaVersion: 1,
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{
										Name:       "binary",
										Version:    "1.2.3",
										Release:    "1",
										Epoch:      2,
										Arch:       "x86_64",
										SrcName:    "src",
										SrcVersion: "1.2.3",
										SrcRelease: "1",
										SrcEpoch:   2,
									},
									{
										Name:       "vim-minimal",
										Version:    "7.4.160",
										Release:    "5.el7",
										Epoch:      2,
										Arch:       "x86_64",
										SrcName:    "vim",
										SrcVersion: "7.4.160",
										SrcRelease: "5.el7",
										SrcEpoch:   2,
									},
								},
							},
						},
						Applications: []types.Application{
							{
								Type:     "composer",
								FilePath: "php-app/composer.lock",
								Libraries: []godeptypes.Library{
									{
										Name:    "guzzlehttp/guzzle",
										Version: "6.2.0",
									},
									{
										Name:    "guzzlehttp/promises",
										Version: "v1.3.1",
									},
								},
							},
						},
						OpaqueDirs:    []string{"etc/"},
						WhiteoutFiles: []string{"etc/hostname"},
					},
				},
				Returns: cache.PutLayerReturns{},
			},
			want: &google_protobuf.Empty{},
		},
		{
			name: "sad path",
			args: args{
				in: &rpcLayer.PutRequest{},
			},
			putLayer: cache.PutLayerExpectation{
				Args: cache.PutLayerArgs{
					LayerIDAnything:             true,
					DecompressedLayerIDAnything: true,
					LayerInfoAnything:           true,
				},
				Returns: cache.PutLayerReturns{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "unable to store layer info in cache",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockCache)
			mockCache.ApplyPutLayerExpectation(tt.putLayer)

			s := NewLayerServer(mockCache)
			got, err := s.Put(context.Background(), tt.args.in)

			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
