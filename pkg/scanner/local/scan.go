package local

import (
	"fmt"
	"sort"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"

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

func (s Scanner) Scan(target string, _ digest.Digest, layerIDs []string, options types.ScanOptions) (report.Results, *ftypes.OS, bool, error) {
	imageDetail, err := s.applier.ApplyLayers(layerIDs)
	if err != nil {
		return nil, nil, false, err
	}

	var eosl bool
	var results report.Results

	if utils.StringInSlice("os", options.VulnType) {
		var result *report.Result
		result, eosl, err = s.scanOSPkg(target, imageDetail.OS.Family, imageDetail.OS.Name, imageDetail.Packages)
		if err != nil {
			return nil, nil, false, err
		}
		if result != nil {
			results = append(results, *result)
		}
	}

	if utils.StringInSlice("library", options.VulnType) {
		libResults, err := s.scanLibrary(imageDetail.Applications)
		if err != nil {
			return nil, nil, false, err
		}
		results = append(results, libResults...)
	}

	return results, imageDetail.OS, eosl, nil
}

func (s Scanner) scanOSPkg(target, osFamily, osName string, pkgs []ftypes.Package) (*report.Result, bool, error) {
	if osFamily == "" {
		return nil, false, nil
	}
	vulns, eosl, err := s.ospkgDetector.Detect(osFamily, osName, pkgs)
	if err != nil && err != ospkgDetector.ErrUnsupportedOS {
		return nil, false, xerrors.Errorf("failed to scan the image: %w", err)
	}

	imageDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osName)
	result := &report.Result{
		Target:          imageDetail,
		Vulnerabilities: vulns,
	}
	return result, eosl, nil
}

func (s Scanner) scanLibrary(apps []ftypes.Application) (report.Results, error) {
	var results report.Results
	for _, app := range apps {
		vulns, err := s.libDetector.Detect(app.FilePath, app.Libraries)
		if err != nil {
			return nil, xerrors.Errorf("failed library scan: %w", err)
		}

		results = append(results, report.Result{
			Target:          app.FilePath,
			Vulnerabilities: vulns,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
}
