package model

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestGetUserLogsOrdersByCreatedAtThenID(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	if err := db.AutoMigrate(&Log{}); err != nil {
		t.Fatalf("failed to migrate log table: %v", err)
	}

	oldLogDB := LOG_DB
	LOG_DB = db
	t.Cleanup(func() {
		LOG_DB = oldLogDB
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})

	logs := []Log{
		{Id: 100, UserId: 7, CreatedAt: 10, Type: LogTypeConsume, Content: "older-high-id"},
		{Id: 2, UserId: 7, CreatedAt: 30, Type: LogTypeConsume, Content: "newer-low-id"},
		{Id: 3, UserId: 7, CreatedAt: 30, Type: LogTypeConsume, Content: "newer-high-id"},
	}
	if err := db.Create(&logs).Error; err != nil {
		t.Fatalf("failed to seed logs: %v", err)
	}

	got, _, err := GetUserLogs(7, LogTypeUnknown, 0, 0, "", "", 0, 10, "", "", "")
	if err != nil {
		t.Fatalf("failed to get user logs: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(got))
	}
	want := []string{"newer-high-id", "newer-low-id", "older-high-id"}
	for i, content := range want {
		if got[i].Content != content {
			t.Fatalf("log %d content = %q, want %q; all logs=%+v", i, got[i].Content, content, got)
		}
	}
}

func TestPostgresPartitionedLogSchemaStatements(t *testing.T) {
	statements := postgresPartitionedLogSchemaStatements()
	joined := strings.Join(statements, "\n")

	for _, want := range []string{
		"CREATE SEQUENCE IF NOT EXISTS public.logs_id_seq",
		"CREATE TABLE IF NOT EXISTS public.logs",
		"PARTITION BY RANGE (created_at)",
		"CREATE INDEX IF NOT EXISTS idx_logs_created_at_id",
		"CREATE INDEX IF NOT EXISTS idx_logs_user_created_id",
		"CREATE INDEX IF NOT EXISTS idx_logs_consume_created_cover",
		"CREATE INDEX IF NOT EXISTS idx_logs_request_id_present",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected schema statements to contain %q, got:\n%s", want, joined)
		}
	}
	if strings.Contains(strings.ToUpper(joined), "PRIMARY KEY") {
		t.Fatalf("partitioned logs schema must not create an id-only primary key:\n%s", joined)
	}
}
