package inspektorgadget

import "github.com/mark3labs/mcp-go/mcp"

// =============================================================================
// Inspektor Gadget gadget related Tool Registrations
// =============================================================================

const (
	observeDNSToolName              = "inspektor_gadget_observe_dns"
	observeTCPToolName              = "inspektor_gadget_observe_tcp"
	observeFileOpenToolName         = "inspektor_gadget_observe_file_open"
	observeProcessExecutionToolName = "inspektor_gadget_observe_process_execution"
	observeSignalToolName           = "inspektor_gadget_observe_signal"
	observeSystemCallsToolName      = "inspektor_gadget_observe_system_calls"
	topFileToolName                 = "inspektor_gadget_top_file"
	topTCPToolName                  = "inspektor_gadget_top_tcp"
)

var commonProperties = []mcp.ToolOption{
	mcp.WithNumber("duration",
		mcp.Description("Duration in seconds to observe TCP traffic. Use '0' for continuous observation until stopped."),
		mcp.DefaultNumber(10),
	),
	mcp.WithString("namespace",
		mcp.Description("The Kubernetes namespace to observe DNS traffic in. If not specified, defaults to all namespaces."),
	),
	mcp.WithString("pod",
		mcp.Description("The specific pod to observe DNS traffic in. If not specified, defaults to all pods in the namespace."),
	),
	mcp.WithString("container",
		mcp.Description("The specific container to observe DNS traffic in. If not specified, defaults to all containers in the pod."),
	),
	mcp.WithString("selector",
		mcp.Description("A label selector to filter pods by labels. If specified, only pods matching the selector will be observed (e.g. -l key1=value1,key2=value2)"),
	),
}

// RegisterInspektorGadgetObserveDNSTool registers the inspektor-gadget tool for DNS tracing
func RegisterInspektorGadgetObserveDNSTool() mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Observe DNS traffic in Kubernetes workloads"),
		mcp.WithString("name",
			mcp.Description("Filter DNS traffic by name. Only DNS queries containing this string will be shown"),
		),
		mcp.WithString("nameserver",
			mcp.Description("Filter DNS traffic by nameserver"),
		),
		mcp.WithString("minimum_latency",
			mcp.Description("Filter DNS traffic by minimum latency in nanaoseconds"),
		),
		mcp.WithString("response_code",
			mcp.Description("Filter DNS traffic by response code"),
			mcp.Enum("Success", "FormatError", "ServerFailure", "NameError", "NotImplemented", "Refused"),
		),
	}
	opts = append(opts, commonProperties...)
	return mcp.NewTool(
		observeDNSToolName,
		opts...,
	)
}

// RegisterInspektorGadgetObserveTCPTool registers the inspektor-gadget tool for TCP tracing
func RegisterInspektorGadgetObserveTCPTool() mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Observe TCP traffic in Kubernetes workloads"),
		mcp.WithString("source_port",
			mcp.Description("Filter TCP traffic by source port"),
		),
		mcp.WithString("destination_port",
			mcp.Description("Filter TCP traffic by destination port"),
		),
		mcp.WithString("event_type",
			mcp.Description("Filter TCP traffic by event type"),
			mcp.Enum("connect", "accept", "close"),
		),
	}
	opts = append(opts, commonProperties...)
	return mcp.NewTool(
		observeTCPToolName,
		opts...,
	)
}

// RegisterInspektorGadgetObserveFileOpenTool registers the inspektor-gadget tool for file open tracing
func RegisterInspektorGadgetObserveFileOpenTool() mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Observe file opening in Kubernetes workloads"),
		mcp.WithString("path",
			mcp.Description("Filter file open events by path. Only file containing this string will be shown"),
		),
	}
	opts = append(opts, commonProperties...)
	return mcp.NewTool(
		observeFileOpenToolName,
		opts...,
	)
}

// RegisterInspektorGadgetObserveProcessExecutionTool registers the inspektor-gadget tool for process execution tracing
func RegisterInspektorGadgetObserveProcessExecutionTool() mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Observe process execution in Kubernetes workloads"),
	}
	opts = append(opts, commonProperties...)
	return mcp.NewTool(
		observeProcessExecutionToolName,
		opts...,
	)
}

// RegisterInspektorGadgetObserveSignalTool registers the inspektor-gadget tool for signal tracing
func RegisterInspektorGadgetObserveSignalTool() mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Observe signals in Kubernetes workloads"),
		mcp.WithString("signal",
			mcp.Description("Filter signals by name"),
			mcp.Enum("SIGINT", "SIGTERM", "SIGKILL", "SIGHUP", "SIGURG", "SIGUSR1", "SIGUSR2", "SIGQUIT", "SIGSTOP"),
		),
	}
	opts = append(opts, commonProperties...)
	return mcp.NewTool(
		observeSignalToolName,
		opts...,
	)
}

// RegisterInspektorGadgetObserveSystemCallsTool registers the inspektor-gadget tool for system call tracing
func RegisterInspektorGadgetObserveSystemCallsTool() mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Observe system calls in Kubernetes workloads"),
		mcp.WithString("syscall",
			mcp.Description("Comma-separated list of system calls to observe. If not specified, all system calls will be observed."),
		),
	}
	opts = append(opts, commonProperties...)
	return mcp.NewTool(
		observeSystemCallsToolName,
		opts...,
	)
}

// RegisterInspektorGadgetTopFileTool registers the inspektor-gadget tool for top file tracing
func RegisterInspektorGadgetTopFileTool() mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Observe top file access in Kubernetes workloads"),
		mcp.WithNumber("max_entries",
			mcp.Description("Maximum number of entries to return. Defaults to 10."),
			mcp.DefaultNumber(10),
		),
	}
	opts = append(opts, commonProperties...)
	return mcp.NewTool(
		topFileToolName,
		opts...,
	)
}

// RegisterInspektorGadgetTopTCPTool registers the inspektor-gadget tool for top TCP tracing
func RegisterInspektorGadgetTopTCPTool() mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Observe top TCP connections in Kubernetes workloads"),
		mcp.WithNumber("max_entries",
			mcp.Description("Maximum number of entries to return. Defaults to 10."),
			mcp.DefaultNumber(10),
		),
	}
	opts = append(opts, commonProperties...)
	return mcp.NewTool(
		topTCPToolName,
		opts...,
	)
}

// =============================================================================
// Inspektor Gadget gadget lifecycle Tool Registrations
// =============================================================================

// RegisterInspektorGadgetGetGadgetResultsTool registers the inspektor-gadget tool to get results of a gadget
func RegisterInspektorGadgetGetGadgetResultsTool() mcp.Tool {
	return mcp.NewTool(
		"inspektor_gadget_get_gadget_results",
		mcp.WithDescription("Get results of the last observation run"),
		mcp.WithString("id",
			mcp.Required(),
			mcp.Description("The ID of the observation run to retrieve results for. This ID is returned when started the gadget for continuous observation"),
		),
	)
}

// RegisterInspektorGadgetStopGadgetTool registers the inspektor-gadget tool to stop a gadget
func RegisterInspektorGadgetStopGadgetTool() mcp.Tool {
	return mcp.NewTool(
		"inspektor_gadget_stop_gadget",
		mcp.WithDescription("Stop a running gadget"),
		mcp.WithString("id",
			mcp.Required(),
			mcp.Description("The ID of the observation run to stop. This ID is returned when started the gadget for continuous observation. Use `inspektor_gadget_get_gadget_results` to retrieve results before stopping."),
		),
	)
}

// RegisterInspektorGadgetListGadgetsTool registers the inspektor-gadget tool to list all running gadgets
func RegisterInspektorGadgetListGadgetsTool() mcp.Tool {
	return mcp.NewTool(
		"inspektor_gadget_list_gadgets",
		mcp.WithDescription("List all running gadgets"),
	)
}

// =============================================================================
// Inspektor Gadget deploy/undeploy Tool Registrations
// =============================================================================

// RegisterInspektorGadgetDeployTool registers the inspektor-gadget tool to deploy Inspektor Gadget
func RegisterInspektorGadgetDeployTool() mcp.Tool {
	return mcp.NewTool(
		"inspektor_gadget_deploy",
		mcp.WithDescription("Deploy Inspektor Gadget in the Kubernetes cluster"),
		mcp.WithString("chart_version",
			mcp.Description("The version of the Inspektor Gadget Helm chart to deploy. Only set this if user explicitly wants to deploy a specific version"),
		),
	)
}

// RegisterInspektorGadgetUndeployTool registers the inspektor-gadget tool to undeploy Inspektor Gadget
func RegisterInspektorGadgetUndeployTool() mcp.Tool {
	return mcp.NewTool(
		"inspektor_gadget_undeploy",
		mcp.WithDescription("Undeploy Inspektor Gadget from the Kubernetes cluster"),
	)
}
