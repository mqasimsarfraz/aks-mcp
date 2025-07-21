package server

import (
	"fmt"
	"log"

	"github.com/Azure/aks-mcp/internal/azcli"
	"github.com/Azure/aks-mcp/internal/azureclient"
	"github.com/Azure/aks-mcp/internal/components/advisor"
	"github.com/Azure/aks-mcp/internal/components/azaks"
	"github.com/Azure/aks-mcp/internal/components/compute"
	"github.com/Azure/aks-mcp/internal/components/detectors"
	"github.com/Azure/aks-mcp/internal/components/fleet"
	"github.com/Azure/aks-mcp/internal/components/inspektorgadget"
	"github.com/Azure/aks-mcp/internal/components/monitor"
	"github.com/Azure/aks-mcp/internal/components/monitor/diagnostics"
	"github.com/Azure/aks-mcp/internal/components/network"
	"github.com/Azure/aks-mcp/internal/config"
	"github.com/Azure/aks-mcp/internal/k8s"
	"github.com/Azure/aks-mcp/internal/tools"
	"github.com/Azure/aks-mcp/internal/version"
	"github.com/Azure/mcp-kubernetes/pkg/cilium"
	"github.com/Azure/mcp-kubernetes/pkg/helm"
	"github.com/Azure/mcp-kubernetes/pkg/kubectl"
	"github.com/mark3labs/mcp-go/server"
)

// Service represents the MCP Kubernetes service
type Service struct {
	cfg       *config.ConfigData
	mcpServer *server.MCPServer
}

// NewService creates a new MCP Kubernetes service
func NewService(cfg *config.ConfigData) *Service {
	return &Service{
		cfg: cfg,
	}
}

// Initialize initializes the service
func (s *Service) Initialize() error {
	// Initialize configuration

	// Create MCP server
	s.mcpServer = server.NewMCPServer(
		"AKS MCP",
		version.GetVersion(),
		server.WithResourceCapabilities(true, true),
		server.WithLogging(),
		server.WithRecovery(),
	)

	// // Register generic az tool
	// azTool := az.RegisterAz()
	// s.mcpServer.AddTool(azTool, tools.CreateToolHandler(az.NewExecutor(), s.cfg))

	// Register individual az commands
	s.registerAzCommands()

	// Register Azure resource tools (VNet, NSG, etc.)
	s.registerAzureResourceTools()

	// Register Azure Advisor tools
	s.registerAdvisorTools()

	// Register AKS Control Plane tools
	s.registerControlPlaneTools()

	// Register Kubernetes tools
	s.registerKubernetesTools()

	return nil
}

// Run starts the service with the specified transport
func (s *Service) Run() error {
	log.Println("MCP Kubernetes version:", version.GetVersion())

	// Start the server
	switch s.cfg.Transport {
	case "stdio":
		log.Println("MCP Kubernetes version:", version.GetVersion())
		log.Println("Listening for requests on STDIO...")
		return server.ServeStdio(s.mcpServer)
	case "sse":
		sse := server.NewSSEServer(s.mcpServer)
		addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
		log.Printf("SSE server listening on %s", addr)
		return sse.Start(addr)
	case "streamable-http":
		streamableServer := server.NewStreamableHTTPServer(s.mcpServer)
		addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
		log.Printf("Streamable HTTP server listening on %s", addr)
		return streamableServer.Start(addr)
	default:
		return fmt.Errorf("invalid transport type: %s (must be 'stdio', 'sse' or 'streamable-http')", s.cfg.Transport)
	}
}

// registerAzCommands registers individual az commands as separate tools
func (s *Service) registerAzCommands() {
	// Register read-only az commands (available at all access levels)
	for _, cmd := range azaks.GetReadOnlyAzCommands() {
		log.Println("Registering az command:", cmd.Name)
		azTool := azaks.RegisterAzCommand(cmd)
		commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
		s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
	}

	// Register read-only az monitor commands (available at all access levels)
	for _, cmd := range monitor.GetReadOnlyMonitorCommands() {
		log.Println("Registering az monitor command:", cmd.Name)
		azTool := monitor.RegisterMonitorCommand(cmd)
		commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
		s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
	}

	// Register generic az fleet tool with structured parameters (available at all access levels)
	log.Println("Registering az fleet tool: az_fleet")
	fleetTool := fleet.RegisterFleet()
	s.mcpServer.AddTool(fleetTool, tools.CreateToolHandler(azcli.NewFleetExecutor(), s.cfg))

	// Register Azure Resource Health monitoring tool (available at all access levels)
	log.Println("Registering monitor tool: az_monitor_activity_log_resource_health")
	resourceHealthTool := monitor.RegisterResourceHealthTool()
	s.mcpServer.AddTool(resourceHealthTool, tools.CreateResourceHandler(monitor.GetResourceHealthHandler(s.cfg), s.cfg))

	// Register Azure Application Insights monitoring tool (available at all access levels)
	log.Println("Registering monitor tool: az_monitor_app_insights_query")
	appInsightsTool := monitor.RegisterAppInsightsQueryTool()
	s.mcpServer.AddTool(appInsightsTool, tools.CreateResourceHandler(monitor.GetAppInsightsHandler(s.cfg), s.cfg))

	// Register account management commands (available at all access levels)
	for _, cmd := range azaks.GetAccountAzCommands() {
		log.Println("Registering az command:", cmd.Name)
		azTool := azaks.RegisterAzCommand(cmd)
		commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
		s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
	}

	// Register read-write commands if access level is readwrite or admin
	if s.cfg.AccessLevel == "readwrite" || s.cfg.AccessLevel == "admin" {
		// Register read-write az commands
		for _, cmd := range azaks.GetReadWriteAzCommands() {
			log.Println("Registering az command:", cmd.Name)
			azTool := azaks.RegisterAzCommand(cmd)
			commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
			s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
		}

		// Register read-write az monitor commands
		for _, cmd := range monitor.GetReadWriteMonitorCommands() {
			log.Println("Registering az monitor command:", cmd.Name)
			azTool := monitor.RegisterMonitorCommand(cmd)
			commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
			s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
		}

		// Fleet commands are handled by the generic az fleet tool registered above
		// No additional registration needed for read-write access
	}

	// Register admin commands only if access level is admin
	if s.cfg.AccessLevel == "admin" {
		// Register admin az commands
		for _, cmd := range azaks.GetAdminAzCommands() {
			log.Println("Registering az command:", cmd.Name)
			azTool := azaks.RegisterAzCommand(cmd)
			commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
			s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
		}

		// Register admin az monitor commands
		for _, cmd := range monitor.GetAdminMonitorCommands() {
			log.Println("Registering az monitor command:", cmd.Name)
			azTool := monitor.RegisterMonitorCommand(cmd)
			commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
			s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
		}

		// Fleet commands are handled by the generic az fleet tool registered above
		// No additional registration needed for admin access
	}
}

// registerControlPlaneTools registers all AKS control plane log-related tools
func (s *Service) registerControlPlaneTools() {
	log.Println("Registering AKS Control Plane tools...")

	// Register diagnostic settings tool
	log.Println("Registering control plane tool: aks_control_plane_diagnostic_settings")
	diagnosticTool := monitor.RegisterControlPlaneDiagnosticSettingsTool()
	s.mcpServer.AddTool(diagnosticTool, tools.CreateResourceHandler(diagnostics.GetControlPlaneDiagnosticSettingsHandler(s.cfg), s.cfg))

	// Register logs querying tool
	log.Println("Registering control plane tool: aks_control_plane_logs")
	logsTool := monitor.RegisterControlPlaneLogsTool()
	s.mcpServer.AddTool(logsTool, tools.CreateResourceHandler(diagnostics.GetControlPlaneLogsHandler(s.cfg), s.cfg))
}

func (s *Service) registerAzureResourceTools() {
	// Create Azure client for the resource tools (cache is internal to the client)
	azClient, err := azureclient.NewAzureClient(s.cfg)
	if err != nil {
		log.Printf("Warning: Failed to create Azure client: %v", err)
		return
	}

	// Register Network-related tools
	s.registerNetworkTools(azClient)

	// Register Detector tools
	s.registerDetectorTools(azClient)

	// Register Compute-related tools
	s.registerComputeTools(azClient)

	// TODO: Add other resource categories in the future:
}

// registerNetworkTools registers all network-related Azure resource tools
func (s *Service) registerNetworkTools(azClient *azureclient.AzureClient) {
	log.Println("Registering Network tools...")

	// Register VNet info tool
	log.Println("Registering network tool: get_vnet_info")
	vnetTool := network.RegisterVNetInfoTool()
	s.mcpServer.AddTool(vnetTool, tools.CreateResourceHandler(network.GetVNetInfoHandler(azClient, s.cfg), s.cfg))

	// Register NSG info tool
	log.Println("Registering network tool: get_nsg_info")
	nsgTool := network.RegisterNSGInfoTool()
	s.mcpServer.AddTool(nsgTool, tools.CreateResourceHandler(network.GetNSGInfoHandler(azClient, s.cfg), s.cfg))

	// Register RouteTable info tool
	log.Println("Registering network tool: get_route_table_info")
	routeTableTool := network.RegisterRouteTableInfoTool()
	s.mcpServer.AddTool(routeTableTool, tools.CreateResourceHandler(network.GetRouteTableInfoHandler(azClient, s.cfg), s.cfg))

	// Register Subnet info tool
	log.Println("Registering network tool: get_subnet_info")
	subnetTool := network.RegisterSubnetInfoTool()
	s.mcpServer.AddTool(subnetTool, tools.CreateResourceHandler(network.GetSubnetInfoHandler(azClient, s.cfg), s.cfg))

	// Register Load Balancers info tool
	log.Println("Registering network tool: get_load_balancers_info")
	lbTool := network.RegisterLoadBalancersInfoTool()
	s.mcpServer.AddTool(lbTool, tools.CreateResourceHandler(network.GetLoadBalancersInfoHandler(azClient, s.cfg), s.cfg))

	// Register Private Endpoint info tool
	log.Println("Registering network tool: get_private_endpoint_info")
	privateEndpointTool := network.RegisterPrivateEndpointInfoTool()
	s.mcpServer.AddTool(privateEndpointTool, tools.CreateResourceHandler(network.GetPrivateEndpointInfoHandler(azClient, s.cfg), s.cfg))
}

// registerDetectorTools registers all detector-related Azure resource tools
func (s *Service) registerDetectorTools(azClient *azureclient.AzureClient) {
	log.Println("Registering Detector tools...")

	// Register list detectors tool
	log.Println("Registering detector tool: list_detectors")
	listTool := detectors.RegisterListDetectorsTool()
	s.mcpServer.AddTool(listTool, tools.CreateResourceHandler(detectors.GetListDetectorsHandler(azClient, s.cfg), s.cfg))

	// Register run detector tool
	log.Println("Registering detector tool: run_detector")
	runTool := detectors.RegisterRunDetectorTool()
	s.mcpServer.AddTool(runTool, tools.CreateResourceHandler(detectors.GetRunDetectorHandler(azClient, s.cfg), s.cfg))

	// Register run detectors by category tool
	log.Println("Registering detector tool: run_detectors_by_category")
	categoryTool := detectors.RegisterRunDetectorsByCategoryTool()
	s.mcpServer.AddTool(categoryTool, tools.CreateResourceHandler(detectors.GetRunDetectorsByCategoryHandler(azClient, s.cfg), s.cfg))
}

// registerComputeTools registers all compute-related Azure resource tools (VMSS/VM)
func (s *Service) registerComputeTools(azClient *azureclient.AzureClient) {
	log.Println("Registering Compute tools...")

	// Register AKS VMSS info tool (supports both single node pool and all node pools)
	log.Println("Registering compute tool: get_aks_vmss_info")
	vmssInfoTool := compute.RegisterAKSVMSSInfoTool()
	s.mcpServer.AddTool(vmssInfoTool, tools.CreateResourceHandler(compute.GetAKSVMSSInfoHandler(azClient, s.cfg), s.cfg))

	// Register read-only az vmss commands (available at all access levels)
	for _, cmd := range compute.GetReadOnlyVmssCommands() {
		log.Println("Registering az vmss command:", cmd.Name)
		azTool := compute.RegisterAzComputeCommand(cmd)
		commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
		s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
	}

	// Register read-write commands if access level is readwrite or admin
	if s.cfg.AccessLevel == "readwrite" || s.cfg.AccessLevel == "admin" {
		// Register read-write az vmss commands
		for _, cmd := range compute.GetReadWriteVmssCommands() {
			log.Println("Registering az vmss command:", cmd.Name)
			azTool := compute.RegisterAzComputeCommand(cmd)
			commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
			s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
		}
	}

	// Register admin commands only if access level is admin
	if s.cfg.AccessLevel == "admin" {
		// Register admin az vmss commands
		for _, cmd := range compute.GetAdminVmssCommands() {
			log.Println("Registering az vmss command:", cmd.Name)
			azTool := compute.RegisterAzComputeCommand(cmd)
			commandExecutor := azcli.CreateCommandExecutorFunc(cmd.Name)
			s.mcpServer.AddTool(azTool, tools.CreateToolHandler(commandExecutor, s.cfg))
		}
	}
}

// registerAdvisorTools registers all Azure Advisor-related tools
func (s *Service) registerAdvisorTools() {
	log.Println("Registering Advisor tools...")

	// Register Azure Advisor recommendation tool (available at all access levels)
	log.Println("Registering advisor tool: az_advisor_recommendation")
	advisorTool := advisor.RegisterAdvisorRecommendationTool()
	s.mcpServer.AddTool(advisorTool, tools.CreateResourceHandler(advisor.GetAdvisorRecommendationHandler(s.cfg), s.cfg))
}

// registerKubernetesTools registers Kubernetes-related tools (kubectl, helm, cilium)
func (s *Service) registerKubernetesTools() {
	log.Println("Registering Kubernetes tools...")

	// Register kubectl commands based on access level
	s.registerKubectlCommands()

	// Register helm if enabled
	if s.cfg.AdditionalTools["helm"] {
		log.Println("Registering Kubernetes tool: helm")
		helmTool := helm.RegisterHelm()
		helmExecutor := k8s.WrapK8sExecutor(helm.NewExecutor())
		s.mcpServer.AddTool(helmTool, tools.CreateToolHandler(helmExecutor, s.cfg))
	}

	// Register cilium if enabled
	if s.cfg.AdditionalTools["cilium"] {
		log.Println("Registering Kubernetes tool: cilium")
		ciliumTool := cilium.RegisterCilium()
		ciliumExecutor := k8s.WrapK8sExecutor(cilium.NewExecutor())
		s.mcpServer.AddTool(ciliumTool, tools.CreateToolHandler(ciliumExecutor, s.cfg))
	}

	// Register Inspektor Gadget tools for observability
	if s.cfg.AdditionalTools["inspektor-gadget"] {
		log.Println("Registering Kubernetes tool: inspektor-gadget")
		s.registerInspektorGadgetTools()
	}
}

// registerKubectlCommands registers kubectl commands based on access level
func (s *Service) registerKubectlCommands() {
	// Register read-only kubectl commands (available at all access levels)
	for _, cmd := range kubectl.GetReadOnlyKubectlCommands() {
		log.Printf("Registering kubectl command: %s", cmd.Name)
		kubectlTool := kubectl.RegisterKubectlCommand(cmd)
		k8sExecutor := kubectl.CreateCommandExecutorFunc(cmd.Name)
		wrappedExecutor := k8s.WrapK8sExecutorFunc(k8sExecutor)
		s.mcpServer.AddTool(kubectlTool, tools.CreateToolHandler(wrappedExecutor, s.cfg))
	}

	// Register read-write commands if access level is readwrite or admin
	if s.cfg.AccessLevel == "readwrite" || s.cfg.AccessLevel == "admin" {
		for _, cmd := range kubectl.GetReadWriteKubectlCommands() {
			log.Printf("Registering kubectl command: %s", cmd.Name)
			kubectlTool := kubectl.RegisterKubectlCommand(cmd)
			k8sExecutor := kubectl.CreateCommandExecutorFunc(cmd.Name)
			wrappedExecutor := k8s.WrapK8sExecutorFunc(k8sExecutor)
			s.mcpServer.AddTool(kubectlTool, tools.CreateToolHandler(wrappedExecutor, s.cfg))
		}
	}

	// Register admin commands only if access level is admin
	if s.cfg.AccessLevel == "admin" {
		for _, cmd := range kubectl.GetAdminKubectlCommands() {
			log.Printf("Registering kubectl command: %s", cmd.Name)
			kubectlTool := kubectl.RegisterKubectlCommand(cmd)
			k8sExecutor := kubectl.CreateCommandExecutorFunc(cmd.Name)
			wrappedExecutor := k8s.WrapK8sExecutorFunc(k8sExecutor)
			s.mcpServer.AddTool(kubectlTool, tools.CreateToolHandler(wrappedExecutor, s.cfg))
		}
	}
}

// registerInspektorGadgetTools registers all Inspektor Gadget tools for observability
func (s *Service) registerInspektorGadgetTools() {
	gadgetMgr, err := inspektorgadget.NewGadgetManager()
	if err != nil {
		log.Printf("Warning: Failed to create gadget manager: %v", err)
		return
	}

	// Register Inspektor Gadget observes DNS tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_observe_dns")
	inspektorGadgetRun := inspektorgadget.RegisterInspektorGadgetObserveDNSTool()
	s.mcpServer.AddTool(inspektorGadgetRun, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetObserveDNSHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget observes TCP tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_observe_tcp")
	inspektorGadgetTCP := inspektorgadget.RegisterInspektorGadgetObserveTCPTool()
	s.mcpServer.AddTool(inspektorGadgetTCP, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetObserveTCPHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget observes file open tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_observe_file_open")
	inspektorGadgetFileOpen := inspektorgadget.RegisterInspektorGadgetObserveFileOpenTool()
	s.mcpServer.AddTool(inspektorGadgetFileOpen, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetObserveFileOpenHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget observes process execution tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_observe_process_execution")
	inspektorGadgetProcessExec := inspektorgadget.RegisterInspektorGadgetObserveProcessExecutionTool()
	s.mcpServer.AddTool(inspektorGadgetProcessExec, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetObserveProcessExecutionHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget observes signal tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_observe_signal")
	inspektorGadgetSignal := inspektorgadget.RegisterInspektorGadgetObserveSignalTool()
	s.mcpServer.AddTool(inspektorGadgetSignal, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetObserveSignalHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget observes system calls tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_observe_system_calls")
	inspektorGadgetSystemCalls := inspektorgadget.RegisterInspektorGadgetObserveSystemCallsTool()
	s.mcpServer.AddTool(inspektorGadgetSystemCalls, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetObserveSystemCallHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget top file tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_top_file")
	inspektorGadgetTopFile := inspektorgadget.RegisterInspektorGadgetTopFileTool()
	s.mcpServer.AddTool(inspektorGadgetTopFile, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetTopFileHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget top TCP tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_top_tcp")
	inspektorGadgetTopTCP := inspektorgadget.RegisterInspektorGadgetTopTCPTool()
	s.mcpServer.AddTool(inspektorGadgetTopTCP, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetTopTCPHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget get gadget results tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_get_gadget_results")
	inspektorGadgetGetResults := inspektorgadget.RegisterInspektorGadgetGetGadgetResultsTool()
	s.mcpServer.AddTool(inspektorGadgetGetResults, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetGetGadgetResultsHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget stop gadget tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_stop_gadget")
	inspektorGadgetStop := inspektorgadget.RegisterInspektorGadgetStopGadgetTool()
	s.mcpServer.AddTool(inspektorGadgetStop, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetStopGadgetHandler(gadgetMgr, s.cfg), s.cfg))

	// Register Inspektor Gadget list gadgets tool
	log.Println("Registering inspektor-gadget tool: inspektor_gadget_list_gadgets")
	inspektorGadgetList := inspektorgadget.RegisterInspektorGadgetListGadgetsTool()
	s.mcpServer.AddTool(inspektorGadgetList, tools.CreateResourceHandler(inspektorgadget.InspektorGadgetListGadgetsHandler(gadgetMgr, s.cfg), s.cfg))

	if s.cfg.AccessLevel == "readwrite" || s.cfg.AccessLevel == "admin" {
		// Register Inspektor Gadget deploy tool
		log.Println("Registering inspektor-gadget tool: inspektor_gadget_deploy")
		inspektorGadgetDeploy := inspektorgadget.RegisterInspektorGadgetDeployTool()
		inspektorGadgetExecutor := k8s.WrapK8sExecutor(inspektorgadget.InspektorGadgetDeployExecutor(gadgetMgr))
		s.mcpServer.AddTool(inspektorGadgetDeploy, tools.CreateToolHandler(inspektorGadgetExecutor, s.cfg))

		// Register Inspektor Gadget undeploy tool
		log.Println("Registering inspektor-gadget tool: inspektor_gadget_undeploy")
		inspektorGadgetUndeploy := inspektorgadget.RegisterInspektorGadgetUndeployTool()
		inspektorGadgetUndeployExecutor := k8s.WrapK8sExecutorFunc(inspektorgadget.InspektorGadgetUndeployExecutor)
		s.mcpServer.AddTool(inspektorGadgetUndeploy, tools.CreateToolHandler(inspektorGadgetUndeployExecutor, s.cfg))
	}
}
