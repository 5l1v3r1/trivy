package server

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/google/wire"
	digest "github.com/opencontainers/go-digest"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/server/config"
	dbFile "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/aquasecurity/trivy/rpc/detector"
	rpcLayer "github.com/aquasecurity/trivy/rpc/layer"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

var DBWorkerSuperSet = wire.NewSet(
	dbFile.SuperSet,
	newDBWorker,
)

func ListenAndServe(addr string, c config.Config, fsCache cache.FSCache) error {
	requestWg := &sync.WaitGroup{}
	dbUpdateWg := &sync.WaitGroup{}

	withWaitGroup := func(base http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Stop processing requests during DB update
			dbUpdateWg.Wait()

			// Wait for all requests to be processed before DB update
			requestWg.Add(1)
			defer requestWg.Done()

			base.ServeHTTP(w, r)

		})
	}

	go func() {
		worker := initializeDBWorker(true)
		ctx := context.Background()
		for {
			time.Sleep(1 * time.Hour)
			if err := worker.update(ctx, c.AppVersion, c.CacheDir, dbUpdateWg, requestWg); err != nil {
				log.Logger.Errorf("%+v\n", err)
			}
		}
	}()

	mux := http.NewServeMux()

	scanHandler := rpcScanner.NewScannerServer(initializeScanServer(fsCache), nil)
	mux.Handle(rpcScanner.ScannerPathPrefix, withToken(withWaitGroup(scanHandler), c.Token, c.TokenHeader))

	layerHandler := rpcLayer.NewLayerServer(NewLayerServer(fsCache), nil)
	mux.Handle(rpcLayer.LayerPathPrefix, withToken(withWaitGroup(layerHandler), c.Token, c.TokenHeader))

	log.Logger.Infof("Listening %s...", addr)

	return http.ListenAndServe(addr, mux)
}

func withToken(base http.Handler, token, tokenHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && token != r.Header.Get(tokenHeader) {
			detector.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid token"))
			return
		}
		base.ServeHTTP(w, r)
	})
}

type dbWorker struct {
	dbClient dbFile.Operation
}

func newDBWorker(dbClient dbFile.Operation) dbWorker {
	return dbWorker{dbClient: dbClient}
}

func (w dbWorker) update(ctx context.Context, appVersion, cacheDir string,
	dbUpdateWg, requestWg *sync.WaitGroup) error {
	needsUpdate, err := w.dbClient.NeedsUpdate(ctx, appVersion, false, false)
	if err != nil {
		return xerrors.Errorf("failed to check if db needs an update")
	} else if !needsUpdate {
		return nil
	}

	log.Logger.Info("Updating DB...")
	if err = w.hotUpdate(ctx, cacheDir, dbUpdateWg, requestWg); err != nil {
		return xerrors.Errorf("failed DB hot update")
	}
	return nil
}

func (w dbWorker) hotUpdate(ctx context.Context, cacheDir string, dbUpdateWg, requestWg *sync.WaitGroup) error {
	tmpDir, err := ioutil.TempDir("", "db")
	if err != nil {
		return xerrors.Errorf("failed to create a temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := w.dbClient.Download(ctx, tmpDir, false); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}

	log.Logger.Info("Suspending all requests during DB update")
	dbUpdateWg.Add(1)
	defer dbUpdateWg.Done()

	log.Logger.Info("Waiting for all requests to be processed before DB update...")
	requestWg.Wait()

	if err = db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}

	if _, err = utils.CopyFile(db.Path(tmpDir), db.Path(cacheDir)); err != nil {
		return xerrors.Errorf("failed to copy the database file: %w", err)
	}

	log.Logger.Info("Reopening DB...")
	if err = db.Init(cacheDir); err != nil {
		return xerrors.Errorf("failed to open DB: %w", err)
	}

	return nil
}

var ScanSuperSet = wire.NewSet(
	local.SuperSet,
	vulnerability.SuperSet,
	NewScanServer,
)

type ScanServer struct {
	localScanner local.Scanner
	vulnClient   vulnerability.Operation
}

func NewScanServer(s local.Scanner, vulnClient vulnerability.Operation) *ScanServer {
	return &ScanServer{localScanner: s, vulnClient: vulnClient}
}

func (s *ScanServer) Scan(ctx context.Context, in *rpcScanner.ScanRequest) (*rpcScanner.ScanResponse, error) {
	results, os, eosl, err := s.localScanner.Scan(in.Target, digest.Digest(in.ImageId), in.LayerIds)
	if err != nil {
		return nil, err
	}

	for i := range results {
		s.vulnClient.FillInfo(results[i].Vulnerabilities, false)
	}
	return rpc.ConvertToRpcScanResponse(results, os, eosl), nil
}

type LayerServer struct {
	cache cache.Cache
}

func NewLayerServer(c cache.Cache) *LayerServer {
	return &LayerServer{cache: c}
}

func (s *LayerServer) Put(ctx context.Context, in *rpcLayer.PutRequest) (*google_protobuf.Empty, error) {
	layerInfo := rpc.ConvertFromRpcPutRequest(in)
	if err := s.cache.PutLayer(in.LayerId, in.DecompressedLayerId, layerInfo); err != nil {
		return nil, err
	}
	return &google_protobuf.Empty{}, nil
}

func (s *LayerServer) MissingLayers(ctx context.Context, in *rpcLayer.Layers) (*rpcLayer.Layers, error) {
	var layerIDs []string
	for _, layerID := range in.LayerIds {
		b := s.cache.GetLayer(layerID)
		if b == nil {
			layerIDs = append(layerIDs, layerID)
		}
	}
	return &rpcLayer.Layers{LayerIds: layerIDs}, nil
}
