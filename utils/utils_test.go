package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandHomeDirectory(t *testing.T) {
	path := "~/Downloads"
	ExpandHomeDirectory(&path)
	assert.Equal(t, filepath.Join(os.Getenv("HOME"), "Downloads"), path)
}

func TestExpandHomeDirectory_TildeUsername(t *testing.T) {
	// ~otheruser paths should NOT be expanded (only ~ and ~/ are supported)
	path := "~otheruser/files"
	ExpandHomeDirectory(&path)
	assert.Equal(t, "~otheruser/files", path, "should not expand ~username paths")
}

func TestExpandHomeDirectory_JustTilde(t *testing.T) {
	path := "~"
	ExpandHomeDirectory(&path)
	assert.Equal(t, os.Getenv("HOME"), path)
}

func TestCreateTLSConfig_InvalidCAPath(t *testing.T) {
	// tests error handling when CA cert file doesn't exist
	tlsConfig, err := createTLSConfig("/nonexistent/ca.pem", "", "")

	assert.Error(t, err, "should return error for non-existent CA certificate")
	assert.Nil(t, tlsConfig, "should return nil config on error")
}

func TestCreateTLSConfig_InvalidCAPEM(t *testing.T) {
	// tests error handling when CA cert has invalid PEM content
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "invalid-ca.pem")
	err := os.WriteFile(caPath, []byte("invalid pem content"), 0644)
	assert.NoError(t, err)

	tlsConfig, err := createTLSConfig(caPath, "", "")

	assert.Error(t, err, "should return error for invalid PEM content")
	assert.Nil(t, tlsConfig, "should return nil config on error")
}

func TestCreateTLSConfig_InvalidClientCert(t *testing.T) {
	// tests error handling with invalid client certificates
	tmpDir := t.TempDir()
	clientCertPath := filepath.Join(tmpDir, "client.pem")
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")

	err := os.WriteFile(clientCertPath, []byte("dummy cert"), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(clientKeyPath, []byte("dummy key"), 0644)
	assert.NoError(t, err)

	// Should fail because CA cert doesn't exist
	tlsConfig, err := createTLSConfig("/nonexistent/ca.pem", clientCertPath, clientKeyPath)

	assert.Error(t, err, "should fail with invalid certificates")
	assert.Nil(t, tlsConfig, "should return nil on error")
}

func TestInitMySQLConnFromCfg_TLSEnabledInvalidCerts(t *testing.T) {
	// When TLS is enabled but certificates are invalid, function should return nil early
	config := map[string]interface{}{
		"username":       "testuser",
		"password":       "testpass",
		"server":         "localhost:3306",
		"database":       "testdb",
		"tls":            true,
		"caCertPath":     "/nonexistent/ca.pem",
		"clientCertPath": "/nonexistent/client.pem",
		"clientKeyPath":  "/nonexistent/client-key.pem",
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	configJSON, err := json.Marshal(config)
	assert.NoError(t, err)
	err = os.WriteFile(cfgPath, configJSON, 0644)
	assert.NoError(t, err)

	db := InitMySQLConnFromCfg(cfgPath)
	assert.Nil(t, db, "should return nil when TLS config fails")
}
