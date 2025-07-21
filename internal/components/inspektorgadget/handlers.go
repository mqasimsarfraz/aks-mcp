package inspektorgadget

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/aks-mcp/internal/config"
	"github.com/Azure/aks-mcp/internal/tools"
)

// =============================================================================
// Inspektor Gadget gadget related Handler
// =============================================================================

const (
	dnsGadgetImage       = "ghcr.io/inspektor-gadget/gadget/trace_dns:latest"
	tcpGadgetImage       = "ghcr.io/inspektor-gadget/gadget/trace_tcp:latest"
	openGadgetImage      = "ghcr.io/inspektor-gadget/gadget/trace_open:latest"
	execGadgetImage      = "ghcr.io/inspektor-gadget/gadget/trace_exec:latest"
	signalGadgetImage    = "ghcr.io/inspektor-gadget/gadget/trace_signal:latest"
	traceloopGadgetImage = "ghcr.io/inspektor-gadget/gadget/traceloop:latest"
	topfileGadgetImage   = "ghcr.io/inspektor-gadget/gadget/top_file:latest"
	topTcpGadgetImage    = "ghcr.io/inspektor-gadget/gadget/top_tcp:latest"
)

const (
	ParamAllNamespaces = "operator.KubeManager.all-namespaces"
	ParamNamespace     = "operator.KubeManager.namespace"
	ParamPod           = "operator.KubeManager.podname"
	ParamContainer     = "operator.KubeManager.containername"
	ParamSelector      = "operator.KubeManager.selector"
	ParamSort          = "operator.sort.sort"
	ParamLimiter       = "operator.limiter.max-entries"
	ParamFetchInterval = "operator.oci.ebpf.map-fetch-interval"
	ParamFilter        = "operator.filter.filter"
)

const (
	ParamTraceloopSyscall = "operator.oci.wasm.syscall-filters"
)

var ErrNotDeployed = fmt.Errorf("inspektor gadget is not deployed, please deploy it first using 'inspektor_gadget_deploy' tool")

// InspektorGadgetObserveDNSHandler returns a handler to observe DNS traffic in Kubernetes workloads
func InspektorGadgetObserveDNSHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	customParams := func(params map[string]interface{}, gadgetParams map[string]string) {
		var filter []string
		if name, ok := params["name"].(string); ok && name != "" {
			filter = append(filter, fmt.Sprintf("name~%s", name))
		}
		if nameserver, ok := params["nameserver"].(string); ok && nameserver != "" {
			filter = append(filter, fmt.Sprintf("nameserver.addr==%s", nameserver))
		}
		if minimumLatency, ok := params["minimum_latency"].(string); ok && minimumLatency != "" {
			filter = append(filter, fmt.Sprintf("latency_ns_raw>=%s", minimumLatency))
		}
		if responseCode, ok := params["response_code"].(string); ok && responseCode != "" {
			filter = append(filter, fmt.Sprintf("rcode==%s", responseCode))
		}
		if len(filter) > 0 {
			gadgetParams[ParamFilter] = strings.Join(filter, ",")
		}
	}
	return inspektorGadgetTraceHandler(mgr, dnsGadgetImage, observeDNSToolName, customParams)
}

// InspektorGadgetObserveTCPHandler returns a handler to observe TCP traffic in Kubernetes workloads
func InspektorGadgetObserveTCPHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	customParams := func(params map[string]interface{}, gadgetParams map[string]string) {
		var filter []string
		if srcPort, ok := params["source_port"].(string); ok && srcPort != "" {
			filter = append(filter, fmt.Sprintf("src.port==%s", srcPort))
		}
		if dstPort, ok := params["destination_port"].(string); ok && dstPort != "" {
			filter = append(filter, fmt.Sprintf("dst.port==%s", dstPort))
		}
		if typ, ok := params["event_type"].(string); ok && typ != "" {
			filter = append(filter, fmt.Sprintf("type==%s", typ))
		}
		if len(filter) > 0 {
			gadgetParams[ParamFilter] = strings.Join(filter, ",")
		}
	}
	return inspektorGadgetTraceHandler(mgr, tcpGadgetImage, observeTCPToolName, customParams)
}

// InspektorGadgetObserveFileOpenHandler returns a handler to observe file access in Kubernetes workloads
func InspektorGadgetObserveFileOpenHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	customParams := func(params map[string]interface{}, gadgetParams map[string]string) {
		if path, ok := params["path"].(string); ok && path != "" {
			gadgetParams[ParamFilter] = fmt.Sprintf("fname~%s", path)
		}
	}
	return inspektorGadgetTraceHandler(mgr, openGadgetImage, observeFileOpenToolName, customParams)
}

// InspektorGadgetObserveProcessExecutionHandler returns a handler to observe process execution in Kubernetes workloads
func InspektorGadgetObserveProcessExecutionHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	return inspektorGadgetTraceHandler(mgr, execGadgetImage, observeProcessExecutionToolName, nil)
}

// InspektorGadgetObserveSignalHandler returns a handler to observe signals in Kubernetes workloads
func InspektorGadgetObserveSignalHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	customParam := func(params map[string]interface{}, gadgetParams map[string]string) {
		if signalFilter, ok := params["signal"].(string); ok && signalFilter != "" {
			gadgetParams[ParamFilter] = fmt.Sprintf("sig==%s", signalFilter)
		}
	}
	return inspektorGadgetTraceHandler(mgr, signalGadgetImage, observeSignalToolName, customParam)
}

// InspektorGadgetObserveSystemCallHandler returns a handler to observe system calls in Kubernetes workloads
func InspektorGadgetObserveSystemCallHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	customParams := func(params map[string]interface{}, gadgetParams map[string]string) {
		// we need to always set the syscall filter parameter
		gadgetParams[ParamTraceloopSyscall] = ""
		if syscallFilter, ok := params["syscall"].(string); ok && syscallFilter != "" {
			gadgetParams[ParamTraceloopSyscall] = syscallFilter
		}
	}

	return inspektorGadgetTraceHandler(mgr, traceloopGadgetImage, observeSystemCallsToolName, customParams)
}

// InspektorGadgetTopFileHandler returns a handler to observe file access in Kubernetes workloads
func InspektorGadgetTopFileHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	customParams := func(params map[string]interface{}, gadgetParams map[string]string) {
		duration, _ := params["duration"].(float64)
		if duration > 0 {
			// Set the map fetch interval to half of the duration to limit the volume of data fetched
			params[ParamFetchInterval] = (time.Duration(duration) * time.Second) / 2
			// Set default values for sort and limiter parameters
			gadgetParams[ParamSort] = "-rbytes_raw,-wbytes_raw"
			maxEntries, _ := params["max_entries"].(float64)
			if maxEntries > 0 {
				gadgetParams[ParamLimiter] = fmt.Sprintf("%d", int(maxEntries))
			} else {
				gadgetParams[ParamLimiter] = "10"
			}
		}
	}
	return inspektorGadgetTraceHandler(mgr, topfileGadgetImage, topFileToolName, customParams)
}

// InspektorGadgetTopTCPHandler returns a handler to observe TCP traffic in Kubernetes workloads
func InspektorGadgetTopTCPHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	customParams := func(params map[string]interface{}, gadgetParams map[string]string) {
		duration, _ := params["duration"].(float64)
		if duration > 0 {
			// Set the map fetch interval to half of the duration to limit the volume of data fetched
			params[ParamFetchInterval] = (time.Duration(duration) * time.Second) / 2
			// Set default values for sort and limiter parameters
			gadgetParams[ParamSort] = "-sent_raw,-received_raw"
			maxEntries, _ := params["max_entries"].(float64)
			if maxEntries > 0 {
				gadgetParams[ParamLimiter] = fmt.Sprintf("%d", int(maxEntries))
			} else {
				gadgetParams[ParamLimiter] = "10"
			}
		}
	}
	return inspektorGadgetTraceHandler(mgr, topTcpGadgetImage, topTCPToolName, customParams)
}

type customParamFunc func(params map[string]interface{}, gadgetParams map[string]string)

func inspektorGadgetTraceHandler(mgr GadgetManager, gadgetImage string, toolName string, customParams customParamFunc) tools.ResourceHandler {
	return tools.ResourceHandlerFunc(func(params map[string]interface{}, _ *config.ConfigData) (string, error) {
		ctx := context.Background()

		// Validate duration parameter
		duration, ok := params["duration"].(float64)
		if !ok {
			duration = 10
		}

		// Check if Inspektor Gadget is deployed
		deployed, _, err := mgr.IsDeployed(ctx)
		if err != nil {
			return "", fmt.Errorf("checking Inspektor Gadget deployment: %w", err)
		}
		if !deployed {
			return "", ErrNotDeployed
		}

		// Extract kubernetes parameters
		gadgetParams := make(map[string]string)
		if namespace, ok := params["namespace"].(string); ok && namespace != "" {
			gadgetParams[ParamNamespace] = namespace
		} else {
			gadgetParams[ParamAllNamespaces] = "true"
		}
		if pod, ok := params["pod"].(string); ok && pod != "" {
			gadgetParams[ParamPod] = pod
		}
		if container, ok := params["container"].(string); ok && container != "" {
			gadgetParams[ParamContainer] = container
		}
		if selector, ok := params["selector"].(string); ok && selector != "" {
			gadgetParams[ParamSelector] = selector
		}

		// Apply custom parameter if provided
		if customParams != nil {
			customParams(params, gadgetParams)
		}

		// Handle continuous observation (duration = 0)
		if duration == 0 {
			tags := []string{"tool-name=" + toolName}
			id, err := mgr.StartGadget(ctx, gadgetImage, gadgetParams, tags)
			if err != nil {
				return "", fmt.Errorf("starting gadget: %w", err)
			}
			return fmt.Sprintf("Gadget started with ID: %s", id), nil
		}

		// Handle timed observation
		resp, err := mgr.RunGadget(ctx, gadgetImage, gadgetParams, time.Duration(duration)*time.Second)
		if err != nil {
			return "", fmt.Errorf("running gadget: %w", err)
		}

		return resp, nil
	})
}

// =============================================================================
// Inspektor Gadget gadget lifecycle Handlers
// =============================================================================

// InspektorGadgetStopGadgetHandler returns a handler to stop a running gadget
func InspektorGadgetStopGadgetHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	return inspektorGadgetLifecycleHandler(mgr, func(ctx context.Context, mgr GadgetManager, id string) (string, error) {
		err := mgr.StopGadget(ctx, id)
		if err != nil {
			return "", fmt.Errorf("stopping gadget: %w", err)
		}
		return fmt.Sprintf("Gadget with ID %s stopped successfully", id), nil
	})
}

// InspektorGadgetGetGadgetResultsHandler returns a handler to get gadget results
func InspektorGadgetGetGadgetResultsHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	return inspektorGadgetLifecycleHandler(mgr, func(ctx context.Context, mgr GadgetManager, id string) (string, error) {
		results, err := mgr.GetResults(ctx, id)
		if err != nil {
			return "", fmt.Errorf("getting gadget results: %w", err)
		}
		return results, nil
	})
}

// InspektorGadgetListGadgetsHandler returns a handler to list running gadgets
func InspektorGadgetListGadgetsHandler(mgr GadgetManager, cfg *config.ConfigData) tools.ResourceHandler {
	return tools.ResourceHandlerFunc(func(params map[string]interface{}, _ *config.ConfigData) (string, error) {
		gadgets, err := mgr.ListGadgets(context.Background(), nil)
		if err != nil {
			return "", fmt.Errorf("listing gadgets: %w", err)
		}
		JSONData, err := json.Marshal(gadgets)
		if err != nil {
			return "", fmt.Errorf("marshaling gadgets: %w", err)
		}
		return string(JSONData), nil
	})
}

// inspektorGadgetLifecycleHandler is a generic handler for lifecycle operations (stop/get-results)
func inspektorGadgetLifecycleHandler(mgr GadgetManager, operation func(context.Context, GadgetManager, string) (string, error)) tools.ResourceHandler {
	return tools.ResourceHandlerFunc(func(params map[string]interface{}, _ *config.ConfigData) (string, error) {
		ctx := context.Background()

		// Validate ID parameter
		id, ok := params["id"].(string)
		if !ok || id == "" {
			return "", fmt.Errorf("invalid or missing 'id' parameter, must be a non-empty string")
		}

		// Check if Inspektor Gadget is deployed
		deployed, _, err := mgr.IsDeployed(ctx)
		if err != nil {
			return "", fmt.Errorf("checking Inspektor Gadget deployment: %w", err)
		}
		if !deployed {
			return "", ErrNotDeployed
		}

		return operation(ctx, mgr, id)
	})
}
