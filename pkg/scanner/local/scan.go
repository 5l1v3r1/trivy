package local

import (
	"fmt"
	"sort"

	"github.com/aquasecurity/fanal/analyzer"

	"github.com/google/wire"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/photon"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
	ftypes "github.com/aquasecurity/fanal/types"
	libDetector "github.com/aquasecurity/trivy/pkg/detector/library"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/report"
)

var SuperSet = wire.NewSet(
	analyzer.NewApplier,
	ospkgDetector.SuperSet,
	libDetector.SuperSet,
	NewScanner,
)

type Scanner struct {
	applier       analyzer.Applier
	ospkgDetector ospkgDetector.Detector
	libDetector   libDetector.Detector
}

func NewScanner(applier analyzer.Applier, ospkgDetector ospkgDetector.Detector, libDetector libDetector.Detector) Scanner {
	return Scanner{applier: applier, ospkgDetector: ospkgDetector, libDetector: libDetector}
}

func (s Scanner) Scan(target string, _ digest.Digest, layerIDs []string) (report.Results, *ftypes.OS, bool, error) {
	results := report.Results{}

	imageDetail, err := s.applier.ApplyLayers(layerIDs)
	if err != nil {
		return nil, nil, false, err
	}

	vulns, eosl, err := s.ospkgDetector.Detect(imageDetail.OS.Family, imageDetail.OS.Name, imageDetail.Packages)
	if err != nil && err != ospkgDetector.ErrUnsupportedOS {
		return nil, nil, false, xerrors.Errorf("failed to scan the image: %w", err)
	}

	if imageDetail.OS.Family != "" {
		imageDetail := fmt.Sprintf("%s (%s %s)", target, imageDetail.OS.Family, imageDetail.OS.Name)
		results = append(results, report.Result{
			Target:          imageDetail,
			Vulnerabilities: vulns,
		})
	}

	libResults := report.Results{}
	for _, app := range imageDetail.Applications {
		vulns, err := s.libDetector.Detect(app.FilePath, app.Libraries)
		if err != nil {
			return nil, nil, false, xerrors.Errorf("failed library scan: %w", err)
		}

		libResults = append(libResults, report.Result{
			Target:          app.FilePath,
			Vulnerabilities: vulns,
		})
	}
	sort.Slice(libResults, func(i, j int) bool {
		return libResults[i].Target < libResults[j].Target
	})

	results = append(results, libResults...)

	return results, imageDetail.OS, eosl, nil
}
