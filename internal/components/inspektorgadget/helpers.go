package inspektorgadget

import (
	"runtime/debug"
	"strings"
)

// getChartVersionFromBuild retrieves the version of the Inspektor Gadget Helm chart from the build information.
func getChartVersionFromBuild() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/inspektor-gadget/inspektor-gadget" {
				if dep.Version != "" {
					return strings.TrimPrefix(dep.Version, "v")
				}
			}
		}
	}
	return "1.0.0-dev"
}
