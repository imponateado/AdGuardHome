package querylog

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_querylog.sqlite")

	db, err := initDB(dbPath)
	require.NoError(t, err)
	defer db.Close()

	assert.FileExists(t, dbPath)

	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='query_log'").Scan(&tableName)

	assert.NoError(t, err, "table query_log should exist")
	assert.Equal(t, "query_log", tableName)

	expectedCols := []string{
		"id", "timestamp", "q_host", "q_type", "client_id",
		"client_ip", "upstream", "elapsed_ns", "response_code",
		"filtering_result", "is_filtered", "reason",
	}

	for _, col := range expectedCols {
		_, err = db.Prepare("SELECT " + col + " FROM query_log")
		assert.NoError(t, err, "column %s should exist and be selectable", col)
	}
}
