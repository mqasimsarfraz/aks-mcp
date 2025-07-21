package inspektorgadget

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/aks-mcp/internal/config"
)

// MockGadgetManager implements the GadgetManager interface for testing
type MockGadgetManager struct {
	IsDeployedFunc  func(ctx context.Context) (bool, string, error)
	StartGadgetFunc func(ctx context.Context, image string, params map[string]string, tags []string) (string, error)
	RunGadgetFunc   func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error)
	StopGadgetFunc  func(ctx context.Context, id string) error
	GetResultsFunc  func(ctx context.Context, id string) (string, error)
	ListGadgetsFunc func(ctx context.Context, tags []string) ([]*GadgetInstance, error)
	GetInfoFunc     func(ctx context.Context, image string) (*GadgetInfo, error)
	CloseFunc       func() error
}

func (m *MockGadgetManager) IsDeployed(ctx context.Context) (bool, string, error) {
	if m.IsDeployedFunc != nil {
		return m.IsDeployedFunc(ctx)
	}
	return true, "v1.0.0", nil
}

func (m *MockGadgetManager) StartGadget(ctx context.Context, image string, params map[string]string, tags []string) (string, error) {
	if m.StartGadgetFunc != nil {
		return m.StartGadgetFunc(ctx, image, params, tags)
	}
	return "test-gadget-id", nil
}

func (m *MockGadgetManager) RunGadget(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
	if m.RunGadgetFunc != nil {
		return m.RunGadgetFunc(ctx, image, params, duration)
	}
	return "test-gadget-results", nil
}

func (m *MockGadgetManager) StopGadget(ctx context.Context, id string) error {
	if m.StopGadgetFunc != nil {
		return m.StopGadgetFunc(ctx, id)
	}
	return nil
}

func (m *MockGadgetManager) GetResults(ctx context.Context, id string) (string, error) {
	if m.GetResultsFunc != nil {
		return m.GetResultsFunc(ctx, id)
	}
	return "test-results", nil
}

func (m *MockGadgetManager) ListGadgets(ctx context.Context, tags []string) ([]*GadgetInstance, error) {
	if m.ListGadgetsFunc != nil {
		return m.ListGadgetsFunc(ctx, tags)
	}
	return []*GadgetInstance{{ID: "test-id", Tags: []string{"test-tag"}, StartedAt: "2023-01-01T00:00:00Z"}}, nil
}

func (m *MockGadgetManager) GetInfo(ctx context.Context, image string) (*GadgetInfo, error) {
	if m.GetInfoFunc != nil {
		return m.GetInfoFunc(ctx, image)
	}
	return &GadgetInfo{Name: "test-gadget", Image: image}, nil
}

func (m *MockGadgetManager) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// =============================================================================
// Tests for Gadget Handlers
// =============================================================================

func TestInspektorGadgetObserveDNSHandler(t *testing.T) {
	t.Run("successful DNS observation with default duration", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})

	t.Run("successful DNS observation with custom duration", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"duration": 30.0,
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})

	t.Run("continuous observation with zero duration", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"duration": 0.0,
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "Gadget started with ID: test-gadget-id" {
			t.Errorf("Expected 'Gadget started with ID: test-gadget-id', got %s", result)
		}
	})

	t.Run("observation with namespace parameter", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				if params[ParamNamespace] != "test-namespace" {
					t.Errorf("Expected namespace 'test-namespace', got %s", params[ParamNamespace])
				}
				return "test-gadget-results", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"namespace": "test-namespace",
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})

	t.Run("observation with pod parameter", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				if params[ParamPod] != "test-pod" {
					t.Errorf("Expected pod 'test-pod', got %s", params[ParamPod])
				}
				return "test-gadget-results", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"pod": "test-pod",
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})

	t.Run("gadget not deployed", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			IsDeployedFunc: func(ctx context.Context) (bool, string, error) {
				return false, "", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error when gadget not deployed")
		}
		if err != ErrNotDeployed {
			t.Errorf("Expected ErrNotDeployed, got %v", err)
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})

	t.Run("deployment check error", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			IsDeployedFunc: func(ctx context.Context) (bool, string, error) {
				return false, "", errors.New("deployment check failed")
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error when deployment check fails")
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})
}

func TestInspektorGadgetObserveSystemCallHandler(t *testing.T) {
	t.Run("syscall observation with custom syscall filter", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				if params[ParamTraceloopSyscall] != "open,close" {
					t.Errorf("Expected syscall filter 'open,close', got %s", params[ParamTraceloopSyscall])
				}
				return "test-syscall-results", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveSystemCallHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"syscall": "open,close",
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-syscall-results" {
			t.Errorf("Expected 'test-syscall-results', got %s", result)
		}
	})

	t.Run("syscall observation without filter", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				if params[ParamTraceloopSyscall] != "" {
					t.Errorf("Expected empty syscall filter, got %s", params[ParamTraceloopSyscall])
				}
				return "test-syscall-results", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveSystemCallHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-syscall-results" {
			t.Errorf("Expected 'test-syscall-results', got %s", result)
		}
	})
}

func TestInspektorGadgetTopFileHandler(t *testing.T) {
	t.Run("top file with default max entries", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				if params[ParamLimiter] != "10" {
					t.Errorf("Expected max entries '10', got %s", params[ParamLimiter])
				}
				if params[ParamSort] != "-rbytes_raw,-wbytes_raw" {
					t.Errorf("Expected sort parameter '-rbytes_raw,-wbytes_raw', got %s", params[ParamSort])
				}
				return "test-topfile-results", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetTopFileHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"duration": 30.0,
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-topfile-results" {
			t.Errorf("Expected 'test-topfile-results', got %s", result)
		}
	})

	t.Run("top file with custom max entries", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				if params[ParamLimiter] != "20" {
					t.Errorf("Expected max entries '20', got %s", params[ParamLimiter])
				}
				return "test-topfile-results", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetTopFileHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"duration":    30.0,
			"max_entries": 20.0,
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-topfile-results" {
			t.Errorf("Expected 'test-topfile-results', got %s", result)
		}
	})
}

func TestInspektorGadgetTopTCPHandler(t *testing.T) {
	t.Run("top TCP with default max entries", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				if params[ParamLimiter] != "10" {
					t.Errorf("Expected max entries '10', got %s", params[ParamLimiter])
				}
				if params[ParamSort] != "-sent_raw,-received_raw" {
					t.Errorf("Expected sort parameter '-sent_raw,-received_raw', got %s", params[ParamSort])
				}
				return "test-toptcp-results", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetTopTCPHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"duration": 30.0,
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-toptcp-results" {
			t.Errorf("Expected 'test-toptcp-results', got %s", result)
		}
	})
}

// =============================================================================
// Tests for Lifecycle Handlers
// =============================================================================

func TestInspektorGadgetStopGadgetHandler(t *testing.T) {
	t.Run("successful gadget stop", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetStopGadgetHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"id": "test-gadget-id",
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		expectedResult := "Gadget with ID test-gadget-id stopped successfully"
		if result != expectedResult {
			t.Errorf("Expected '%s', got %s", expectedResult, result)
		}
	})

	t.Run("missing id parameter", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetStopGadgetHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error for missing id parameter")
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})

	t.Run("empty id parameter", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetStopGadgetHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"id": "",
		}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error for empty id parameter")
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})

	t.Run("gadget not deployed", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			IsDeployedFunc: func(ctx context.Context) (bool, string, error) {
				return false, "", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetStopGadgetHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"id": "test-gadget-id",
		}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error when gadget not deployed")
		}
		if err != ErrNotDeployed {
			t.Errorf("Expected ErrNotDeployed, got %v", err)
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})

	t.Run("stop gadget error", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			StopGadgetFunc: func(ctx context.Context, id string) error {
				return errors.New("stop failed")
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetStopGadgetHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"id": "test-gadget-id",
		}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error when stop fails")
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})
}

func TestInspektorGadgetGetGadgetResultsHandler(t *testing.T) {
	t.Run("successful get results", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetGetGadgetResultsHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"id": "test-gadget-id",
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-results" {
			t.Errorf("Expected 'test-results', got %s", result)
		}
	})

	t.Run("get results error", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			GetResultsFunc: func(ctx context.Context, id string) (string, error) {
				return "", errors.New("get results failed")
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetGetGadgetResultsHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"id": "test-gadget-id",
		}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error when get results fails")
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})
}

func TestInspektorGadgetListGadgetsHandler(t *testing.T) {
	t.Run("successful list gadgets", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetListGadgetsHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		// Result should be JSON-encoded gadget list
		expectedJSON := `[{"id":"test-id","tags":["test-tag"],"startedAt":"2023-01-01T00:00:00Z"}]`
		if result != expectedJSON {
			t.Errorf("Expected '%s', got %s", expectedJSON, result)
		}
	})

	t.Run("list gadgets error", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			ListGadgetsFunc: func(ctx context.Context, tags []string) ([]*GadgetInstance, error) {
				return nil, errors.New("list failed")
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetListGadgetsHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error when list fails")
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})
}

// =============================================================================
// Tests for Other Observation Handlers
// =============================================================================

func TestInspektorGadgetObserveTCPHandler(t *testing.T) {
	t.Run("successful TCP observation", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveTCPHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})
}

func TestInspektorGadgetObserveFileOpenHandler(t *testing.T) {
	t.Run("successful file open observation", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveFileOpenHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})
}

func TestInspektorGadgetObserveProcessExecutionHandler(t *testing.T) {
	t.Run("successful process execution observation", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveProcessExecutionHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})
}

func TestInspektorGadgetObserveSignalHandler(t *testing.T) {
	t.Run("successful signal observation", func(t *testing.T) {
		mockMgr := &MockGadgetManager{}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveSignalHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})
}

// =============================================================================
// Tests for Common Scenarios
// =============================================================================

func TestHandlersWithAllKubernetesParameters(t *testing.T) {
	t.Run("observation with all kubernetes parameters", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				expectedParams := map[string]string{
					ParamNamespace: "test-namespace",
					ParamPod:       "test-pod",
					ParamContainer: "test-container",
					ParamSelector:  "app=test",
				}

				for key, expectedValue := range expectedParams {
					if params[key] != expectedValue {
						t.Errorf("Expected %s='%s', got %s='%s'", key, expectedValue, key, params[key])
					}
				}

				return "test-gadget-results", nil
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"namespace": "test-namespace",
			"pod":       "test-pod",
			"container": "test-container",
			"selector":  "app=test",
		}

		result, err := handler.Handle(params, cfg)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result != "test-gadget-results" {
			t.Errorf("Expected 'test-gadget-results', got %s", result)
		}
	})
}

func TestHandlersWithRunGadgetError(t *testing.T) {
	t.Run("run gadget error", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			RunGadgetFunc: func(ctx context.Context, image string, params map[string]string, duration time.Duration) (string, error) {
				return "", errors.New("run gadget failed")
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error when run gadget fails")
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})
}

func TestHandlersWithStartGadgetError(t *testing.T) {
	t.Run("start gadget error", func(t *testing.T) {
		mockMgr := &MockGadgetManager{
			StartGadgetFunc: func(ctx context.Context, image string, params map[string]string, tags []string) (string, error) {
				return "", errors.New("start gadget failed")
			},
		}
		cfg := &config.ConfigData{}

		handler := InspektorGadgetObserveDNSHandler(mockMgr, cfg)
		params := map[string]interface{}{
			"duration": 0.0, // This triggers StartGadget
		}

		result, err := handler.Handle(params, cfg)

		if err == nil {
			t.Error("Expected error when start gadget fails")
		}
		if result != "" {
			t.Errorf("Expected empty result on error, got %s", result)
		}
	})
}
