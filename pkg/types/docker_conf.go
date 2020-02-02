package types

import (
	"time"

	"github.com/aquasecurity/fanal/types"
	"github.com/caarlos0/env/v6"
)

type DockerConfig struct {
	UserName string        `env:"TRIVY_USERNAME"`
	Password string        `env:"TRIVY_PASSWORD"`
	Timeout  time.Duration `env:"TRIVY_TIMEOUT_SEC" envDefault:"60s"`
	Insecure bool          `env:"TRIVY_INSECURE" envDefault:"true"`
}

func GetDockerOption() (types.DockerOption, error) {
	cfg := DockerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return types.DockerOption{}, err
	}
	return types.DockerOption{
		UserName:              cfg.UserName,
		Password:              cfg.Password,
		Timeout:               cfg.Timeout,
		InsecureSkipTLSVerify: cfg.Insecure,
	}, nil
}
