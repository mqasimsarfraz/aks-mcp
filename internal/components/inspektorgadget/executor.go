package inspektorgadget

import (
	"context"
	"fmt"

	k8scommand "github.com/Azure/mcp-kubernetes/pkg/command"
	k8sconfig "github.com/Azure/mcp-kubernetes/pkg/config"
	k8stools "github.com/Azure/mcp-kubernetes/pkg/tools"
)

// =============================================================================
// Inspektor Gadget deploy/undeploy Executor
// =============================================================================

const (
	inspektorGadgetChartRelease   = "gadget"
	inspektorGadgetChartNamespace = "gadget"
	inspektorGadgetChartURL       = "oci://ghcr.io/inspektor-gadget/inspektor-gadget/charts/gadget"
)

func InspektorGadgetDeployExecutor(mgr GadgetManager) k8stools.CommandExecutor {
	return k8stools.CommandExecutorFunc(func(params map[string]interface{}, cfg *k8sconfig.ConfigData) (string, error) {
		deployed, _, err := mgr.IsDeployed(context.Background())
		if err != nil {
			return "", fmt.Errorf("checking inspektor gadget deployment status: %w", err)
		}
		if deployed {
			return "", fmt.Errorf("inspektor gadget is already deployed")
		}
		chartVersion, ok := params["chart_version"].(string)
		if !ok || chartVersion == "" {
			chartVersion = getChartVersionFromBuild()
		}
		chartUrl := fmt.Sprintf("%s:%s", inspektorGadgetChartURL, chartVersion)
		helmArgs := fmt.Sprintf("install %s -n %s --create-namespace %s", inspektorGadgetChartRelease, inspektorGadgetChartNamespace, chartUrl)

		// TODO: use security.Validator once helm readwrite/admin operations are implemented
		if !cfg.SecurityConfig.IsNamespaceAllowed(inspektorGadgetChartNamespace) {
			return "", fmt.Errorf("namespace %s is not allowed by security policy", inspektorGadgetChartNamespace)
		}
		process := k8scommand.NewShellProcess("helm", cfg.Timeout)
		return process.Run(helmArgs)
	})
}

func InspektorGadgetUndeployExecutor(params map[string]interface{}, cfg *k8sconfig.ConfigData) (string, error) {
	helmArgs := fmt.Sprintf("uninstall %s -n %s", inspektorGadgetChartRelease, inspektorGadgetChartNamespace)

	// TODO: use security.Validator once helm readwrite/admin operations are implemented
	if !cfg.SecurityConfig.IsNamespaceAllowed(inspektorGadgetChartNamespace) {
		return "", fmt.Errorf("namespace %s is not allowed by security policy", inspektorGadgetChartNamespace)
	}
	process := k8scommand.NewShellProcess("helm", cfg.Timeout)
	return process.Run(helmArgs)
}
