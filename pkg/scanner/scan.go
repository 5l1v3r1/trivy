package scanner

import (
	"context"
	"flag"
	"os"

	"github.com/google/wire"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/docker"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

var StandaloneSet = wire.NewSet(
	types.GetDockerOption,
	docker.NewDockerExtractor,
	wire.Bind(new(extractor.Extractor), new(docker.Extractor)),
	analyzer.New,
	local.SuperSet,
	wire.Bind(new(Driver), new(local.Scanner)),
	NewScanner,
)

var ClientSet = wire.NewSet(
	types.GetDockerOption,
	docker.NewDockerExtractor,
	wire.Bind(new(extractor.Extractor), new(docker.Extractor)),
	analyzer.New,
	client.SuperSet,
	wire.Bind(new(Driver), new(client.Scanner)),
	NewScanner,
)

type Scanner struct {
	cacheClient cache.LayerCache
	driver      Driver
	analyzer    analyzer.Config
}

type Driver interface {
	Scan(target string, imageID digest.Digest, layerIDs []string) (report.Results, *ftypes.OS, bool, error)
}

func NewScanner(driver Driver, ac analyzer.Config, cacheClient cache.LayerCache) Scanner {
	return Scanner{driver: driver, analyzer: ac, cacheClient: cacheClient}
}

func (s Scanner) ScanImage() (report.Results, error) {
	ctx := context.Background()

	//dockerOption, err := types.GetDockerOption()
	//if err != nil {
	//	return nil, xerrors.Errorf("failed to get docker option: %w", err)
	//}
	//
	//if imageName != "" {
	//	dockerOption.Timeout = scanOptions.Timeout
	//}
	//
	//var ext extractor.Extractor
	//var target string
	//if imageName != "" {
	//	target = imageName
	//	ext, err = docker.NewDockerExtractor(ctx, imageName, dockerOption)
	//	if err != nil {
	//		return nil, err
	//	}
	//} else if filePath != "" {
	//	target = filePath
	//	ext, err = docker.NewDockerTarExtractor(ctx, imageName, dockerOption)
	//	if err != nil {
	//		return nil, err
	//	}
	//} else {
	//	return nil, xerrors.New("image name or image file must be specified")
	//}
	//
	//ac := analyzer.New(ext, s.cacheClient)
	imageInfo, err := s.analyzer.Analyze(ctx)
	if err != nil {
		return nil, err
	}

	results, osFound, eosl, err := s.driver.Scan(imageInfo.Name, imageInfo.ID, imageInfo.LayerIDs)
	if err != nil {
		return nil, err
	}
	if eosl {
		log.Logger.Warnf("This OS version is no longer supported by the distribution: %s %s", osFound.Family, osFound.Name)
		log.Logger.Warnf("The vulnerability detection may be insufficient because security updates are not provided")
	}

	//if utils.StringInSlice("os", scanOptions.VulnType) {
	//	osFamily, osVersion, osVulns, err := s.ospkgScanner.Scan(files)
	//	if err != nil && err != ospkgDetector.ErrUnsupportedOS {
	//		return nil, xerrors.Errorf("failed to scan the image: %w", err)
	//	}
	//	if osFamily != "" {
	//		imageDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osVersion)
	//		results = append(results, report.Result{
	//			Target:          imageDetail,
	//			Vulnerabilities: osVulns,
	//		})
	//	}
	//}
	//
	//if utils.StringInSlice("library", scanOptions.VulnType) {
	//	libVulns, err := s.libScanner.Scan(files)
	//	if err != nil {
	//		return nil, xerrors.Errorf("failed to scan libraries: %w", err)
	//	}
	//
	//	var libResults report.Results
	//	for path, vulns := range libVulns {
	//		libResults = append(libResults, report.Result{
	//			Target:          path,
	//			Vulnerabilities: vulns,
	//		})
	//	}
	//	sort.Slice(libResults, func(i, j int) bool {
	//		return libResults[i].Target < libResults[j].Target
	//	})
	//	results = append(results, libResults...)
	//}

	return results, nil
}

func openStream(path string) (*os.File, error) {
	if path == "-" {
		if terminal.IsTerminal(0) {
			flag.Usage()
			os.Exit(64)
		} else {
			return os.Stdin, nil
		}
	}
	return os.Open(path)
}
