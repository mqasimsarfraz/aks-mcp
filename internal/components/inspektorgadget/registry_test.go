package inspektorgadget

import (
	"testing"
)

// =============================================================================
// Tests for Inspektor Gadget gadget related Tool Registrations
// =============================================================================

func TestRegisterInspektorGadgetObserveDNSTool(t *testing.T) {
	tool := RegisterInspektorGadgetObserveDNSTool()

	if tool.Name != observeDNSToolName {
		t.Errorf("Expected tool name '%s', got %s", observeDNSToolName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetObserveTCPTool(t *testing.T) {
	tool := RegisterInspektorGadgetObserveTCPTool()

	if tool.Name != observeTCPToolName {
		t.Errorf("Expected tool name '%s', got %s", observeTCPToolName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetObserveFileOpenTool(t *testing.T) {
	tool := RegisterInspektorGadgetObserveFileOpenTool()

	if tool.Name != observeFileOpenToolName {
		t.Errorf("Expected tool name '%s', got %s", observeFileOpenToolName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetObserveProcessExecutionTool(t *testing.T) {
	tool := RegisterInspektorGadgetObserveProcessExecutionTool()

	if tool.Name != observeProcessExecutionToolName {
		t.Errorf("Expected tool name '%s', got %s", observeProcessExecutionToolName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetObserveSignalTool(t *testing.T) {
	tool := RegisterInspektorGadgetObserveSignalTool()

	if tool.Name != observeSignalToolName {
		t.Errorf("Expected tool name '%s', got %s", observeSignalToolName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetObserveSystemCallsTool(t *testing.T) {
	tool := RegisterInspektorGadgetObserveSystemCallsTool()

	if tool.Name != observeSystemCallsToolName {
		t.Errorf("Expected tool name '%s', got %s", observeSystemCallsToolName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetTopFileTool(t *testing.T) {
	tool := RegisterInspektorGadgetTopFileTool()

	if tool.Name != topFileToolName {
		t.Errorf("Expected tool name '%s', got %s", topFileToolName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetTopTCPTool(t *testing.T) {
	tool := RegisterInspektorGadgetTopTCPTool()

	if tool.Name != topTCPToolName {
		t.Errorf("Expected tool name '%s', got %s", topTCPToolName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

// =============================================================================
// Tests for Inspektor Gadget gadget lifecycle Tool Registrations
// =============================================================================

func TestRegisterInspektorGadgetGetGadgetResultsTool(t *testing.T) {
	tool := RegisterInspektorGadgetGetGadgetResultsTool()

	expectedName := "inspektor_gadget_get_gadget_results"
	if tool.Name != expectedName {
		t.Errorf("Expected tool name '%s', got %s", expectedName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetStopGadgetTool(t *testing.T) {
	tool := RegisterInspektorGadgetStopGadgetTool()

	expectedName := "inspektor_gadget_stop_gadget"
	if tool.Name != expectedName {
		t.Errorf("Expected tool name '%s', got %s", expectedName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetListGadgetsTool(t *testing.T) {
	tool := RegisterInspektorGadgetListGadgetsTool()

	expectedName := "inspektor_gadget_list_gadgets"
	if tool.Name != expectedName {
		t.Errorf("Expected tool name '%s', got %s", expectedName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

// =============================================================================
// Tests for Inspektor Gadget deploy/undeploy Tool Registrations
// =============================================================================

func TestRegisterInspektorGadgetDeployTool(t *testing.T) {
	tool := RegisterInspektorGadgetDeployTool()

	expectedName := "inspektor_gadget_deploy"
	if tool.Name != expectedName {
		t.Errorf("Expected tool name '%s', got %s", expectedName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestRegisterInspektorGadgetUndeployTool(t *testing.T) {
	tool := RegisterInspektorGadgetUndeployTool()

	expectedName := "inspektor_gadget_undeploy"
	if tool.Name != expectedName {
		t.Errorf("Expected tool name '%s', got %s", expectedName, tool.Name)
	}

	if tool.Description == "" {
		t.Error("Expected tool description to be set")
	}
}

func TestCommonPropertiesExist(t *testing.T) {
	if len(commonProperties) == 0 {
		t.Error("Expected commonProperties to contain at least one property")
	}

	// Verify we have the expected number of common properties
	expectedPropertyCount := 5 // duration, namespace, pod, container, selector
	if len(commonProperties) != expectedPropertyCount {
		t.Errorf("Expected %d common properties, got %d", expectedPropertyCount, len(commonProperties))
	}
}
