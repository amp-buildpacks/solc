// Copyright (c) The Amphitheatre Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package solc

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/crush"
	"github.com/paketo-buildpacks/libpak/effect"
	"github.com/paketo-buildpacks/libpak/sbom"
	"github.com/paketo-buildpacks/libpak/sherpa"
)

type Solc struct {
	LayerContributor libpak.DependencyLayerContributor
	Logger           bard.Logger
	Executor         effect.Executor
}

func NewSolc(dependency libpak.BuildpackDependency, cache libpak.DependencyCache) Solc {
	contributor := libpak.NewDependencyLayerContributor(dependency, cache, libcnb.LayerTypes{
		Build:  true,
		Cache:  true,
		Launch: true,
	})
	return Solc{
		LayerContributor: contributor,
		Executor:         effect.NewExecutor(),
	}
}

func (r Solc) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	r.LayerContributor.Logger = r.Logger
	return r.LayerContributor.Contribute(layer, func(artifact *os.File) (libcnb.Layer, error) {
		bin := filepath.Join(layer.Path, "bin")

		r.Logger.Bodyf("Expanding %s to %s", artifact.Name(), bin)
		if err := crush.Extract(artifact, layer.Path, 1); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to expand %s\n%w", artifact.Name(), err)
		}

		r.Logger.Bodyf("Setting %s in PATH", bin)
		if err := os.Setenv("PATH", sherpa.AppendToEnvVar("PATH", ":", bin)); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to set $PATH\n%w", err)
		}

		buf := &bytes.Buffer{}
		npm := filepath.Join(bin, "npm")
		if err := r.Executor.Execute(effect.Execution{
			Command: npm,
			Args:    []string{"install", "solc", "-g"},
			Stdout:  buf,
			Stderr:  buf,
		}); err != nil {
			return libcnb.Layer{}, fmt.Errorf("error executing '%s':\n Combined Output: %s: \n%w", npm, buf.String(), err)
		}

		buf = &bytes.Buffer{}
		if err := r.Executor.Execute(effect.Execution{
			Command: "solcjs",
			Args:    []string{"--version"},
			Stdout:  buf,
			Stderr:  buf,
		}); err != nil {
			return libcnb.Layer{}, fmt.Errorf("error executing 'solcjs --version':\n Combined Output: %s: \n%w", buf.String(), err)
		}
		version := strings.TrimSpace(buf.String())
		r.Logger.Bodyf("Checking solc version: %s", version)

		sbomPath := layer.SBOMPath(libcnb.SyftJSON)
		dep := sbom.NewSyftDependency(layer.Path, []sbom.SyftArtifact{
			{
				ID:      "solc",
				Name:    "Solc",
				Version: version,
				Type:    "UnknownPackage",
				FoundBy: "amp-buildpacks/solc",
				Locations: []sbom.SyftLocation{
					{Path: "amp-buildpacks/solc/solc/solc.go"},
				},
				Licenses: []string{"Apache-2.0"},
				CPEs:     []string{fmt.Sprintf("cpe:2.3:a:solc:solc:%s:*:*:*:*:*:*:*", version)},
				PURL:     fmt.Sprintf("pkg:generic/solc@%s", version),
			},
		})
		r.Logger.Debugf("Writing Syft SBOM at %s: %+v", sbomPath, dep)
		if err := dep.WriteTo(sbomPath); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to write SBOM\n%w", err)
		}
		return layer, nil
	})
}

func (r Solc) BuildProcessTypes(enableProcess string) ([]libcnb.Process, error) {
	processes := []libcnb.Process{}

	if enableProcess == "true" {
		processes = append(processes, libcnb.Process{
			Type:    "web",
			Command: "npm start",
			Default: true,
		})
	}
	return processes, nil
}

func (r Solc) Name() string {
	return r.LayerContributor.LayerName()
}
