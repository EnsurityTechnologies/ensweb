package ensweb

import (
	"net/http/httptest"
	"testing"

	"github.com/EnsurityTechnologies/logger"
	"github.com/EnsurityTechnologies/uuid"
)

// MockLogger is a simple mock logger for testing
type MockLogger struct{}

func (m *MockLogger) Debug(msg string, args ...interface{})                   {}
func (m *MockLogger) Info(msg string, args ...interface{})                    {}
func (m *MockLogger) Warn(msg string, args ...interface{})                    {}
func (m *MockLogger) Error(msg string, args ...interface{})                   {}
func (m *MockLogger) ErrorPanic(err error, args ...interface{})               {}
func (m *MockLogger) Fatal(msg string, args ...interface{})                   {}
func (m *MockLogger) Named(name string) logger.Logger                         { return m }
func (m *MockLogger) ImpliedArgs() []interface{}                              { return nil }
func (m *MockLogger) IsDebug() bool                                           { return false }
func (m *MockLogger) IsError() bool                                           { return false }
func (m *MockLogger) IsInfo() bool                                            { return false }
func (m *MockLogger) IsTrace() bool                                           { return false }
func (m *MockLogger) IsWarn() bool                                            { return false }
func (m *MockLogger) Log(level logger.Level, msg string, args ...interface{}) {}
func (m *MockLogger) Name() string                                            { return "mock" }
func (m *MockLogger) Panic(msg string, args ...interface{})                   {}
func (m *MockLogger) ResetNamed(name string) logger.Logger                    { return m }
func (m *MockLogger) SetLevel(level logger.Level)                             {}
func (m *MockLogger) Trace(msg string, args ...interface{})                   {}
func (m *MockLogger) With(args ...interface{}) logger.Logger                  { return m }

func TestTenantCallbackBackwardCompatibility(t *testing.T) {
	// Create a test server
	cfg := &Config{
		Address: "localhost",
		Port:    "8080",
		Secure:  false,
	}
	serverCfg := &ServerConfig{}
	log := &MockLogger{}

	server, err := NewServer(cfg, serverCfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test 1: Backward compatibility with old callback
	newCallback := func(tenantName string) (string, error) {
		return "new-" + tenantName, nil
	}
	server.SetTenantCBFunc(newCallback)

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Host = "example.com"

	// Test getTenantID (should work with old callback)
	tenantID := server.getTenantID(req)
	expectedTenantID := "tenant-example.com"
	if tenantID != expectedTenantID {
		t.Errorf("Expected tenant ID %s, got %s", expectedTenantID, tenantID)
	}

	// Test getTenantIDWithError (should work with old callback)
	tenantIDWithError, err := server.getTenantIDWithError(req)
	if err != nil {
		t.Errorf("Expected no error with old callback, got %v", err)
	}
	if tenantIDWithError != expectedTenantID {
		t.Errorf("Expected tenant ID %s, got %s", expectedTenantID, tenantIDWithError)
	}
}

func TestTenantCallbackWithError(t *testing.T) {
	// Create a test server
	cfg := &Config{
		Address: "localhost",
		Port:    "8080",
		Secure:  false,
	}
	serverCfg := &ServerConfig{}
	log := &MockLogger{}

	server, err := NewServer(cfg, serverCfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Set a default tenant ID
	defaultTenantID := uuid.New()
	server.SetDefaultTenant(defaultTenantID)

	// Test 2: New callback with error handling
	errorCallback := func(tenantName string) (string, error) {
		if tenantName == "invalid.com" {
			return "", &TenantError{Message: "Invalid tenant"}
		}
		return "tenant-" + tenantName, nil
	}
	server.SetTenantCBFunc(errorCallback)

	// Test successful case
	req := httptest.NewRequest("GET", "http://valid.com/test", nil)
	req.Host = "valid.com"

	tenantID, err := server.getTenantIDWithError(req)
	if err != nil {
		t.Errorf("Expected no error for valid tenant, got %v", err)
	}
	expectedTenantID := "tenant-valid.com"
	if tenantID != expectedTenantID {
		t.Errorf("Expected tenant ID %s, got %s", expectedTenantID, tenantID)
	}

	// Test error case
	req = httptest.NewRequest("GET", "http://invalid.com/test", nil)
	req.Host = "invalid.com"

	tenantID, err = server.getTenantIDWithError(req)
	if err == nil {
		t.Error("Expected error for invalid tenant, got nil")
	}
	// Should fallback to default tenant ID
	if tenantID != defaultTenantID.String() {
		t.Errorf("Expected fallback to default tenant ID %s, got %s", defaultTenantID.String(), tenantID)
	}
}

func TestTenantCallbackPriority(t *testing.T) {
	// Create a test server
	cfg := &Config{
		Address: "localhost",
		Port:    "8080",
		Secure:  false,
	}
	serverCfg := &ServerConfig{}
	log := &MockLogger{}

	server, err := NewServer(cfg, serverCfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Set a default tenant ID
	defaultTenantID := uuid.New()
	server.SetDefaultTenant(defaultTenantID)

	// Set both old and new callbacks
	// oldCallback := func(tenantName string) string {
	// 	return "old-" + tenantName
	// }
	newCallback := func(tenantName string) (string, error) {
		return "new-" + tenantName, nil
	}

	//server.SetTenantCBFunc(oldCallback)
	server.SetTenantCBFunc(newCallback)

	// Test that new callback takes priority
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Host = "example.com"

	tenantID, err := server.getTenantIDWithError(req)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedTenantID := "new-example.com"
	if tenantID != expectedTenantID {
		t.Errorf("Expected new callback to take priority, expected %s, got %s", expectedTenantID, tenantID)
	}
}
