package app

import (
	"runtime/debug"

	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/plugin"
)

// Manifest はバイナリに埋め込まれた構成（`iam version --manifest`。design.md 11.12）。
type Manifest struct {
	Version   string                   `json:"version"`
	GoVersion string                   `json:"go_version"`
	Features  []ManifestFeature        `json:"features"`
	Adapters  map[plugin.Kind][]string `json:"adapters"`
}

// ManifestFeature はマニフェストのフィーチャーの1件。
type ManifestFeature struct {
	Name        string   `json:"name"`
	DataVersion int      `json:"data_version"`
	Requires    []string `json:"requires,omitempty"`
}

// BuildManifest はこのバイナリのマニフェストを作る。
func BuildManifest(version string) Manifest {
	m := Manifest{Version: version, Features: []ManifestFeature{}, Adapters: plugin.Registered()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		m.GoVersion = bi.GoVersion
		if m.Version == "" {
			m.Version = bi.Main.Version
		}
	}
	for _, f := range feature.Registered() {
		m.Features = append(m.Features, ManifestFeature{Name: f.Name, DataVersion: f.DataVersion, Requires: f.Requires})
	}
	return m
}
