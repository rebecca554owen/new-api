package model

import (
	"path/filepath"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestMigrateOldLogsToLogDBIfNeeded(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "source.db")
	targetPath := filepath.Join(t.TempDir(), "target.db")

	sourceDB, err := gorm.Open(sqlite.Open(sourcePath), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open source db: %v", err)
	}
	targetDB, err := gorm.Open(sqlite.Open(targetPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open target db: %v", err)
	}
	if err := sourceDB.AutoMigrate(&Log{}); err != nil {
		t.Fatalf("failed to migrate source db: %v", err)
	}
	if err := targetDB.AutoMigrate(&Log{}); err != nil {
		t.Fatalf("failed to migrate target db: %v", err)
	}
	sourceSQLDB, err := sourceDB.DB()
	if err != nil {
		t.Fatalf("failed to get source sql db: %v", err)
	}
	targetSQLDB, err := targetDB.DB()
	if err != nil {
		t.Fatalf("failed to get target sql db: %v", err)
	}

	oldDB := DB
	oldLogDB := LOG_DB
	oldAutoMigrate := common.AutoMigrateOldLogsToLogDB
	oldBatchSize := common.LogMigrationBatchSize
	oldUsingSQLite := common.UsingSQLite
	oldUsingPostgreSQL := common.UsingPostgreSQL
	oldUsingMySQL := common.UsingMySQL
	oldLogSQLType := common.LogSqlType
	oldAllowNonEmptyTarget := common.AllowLogMigrationToNonEmptyTarget
	defer func() {
		DB = oldDB
		LOG_DB = oldLogDB
		common.AutoMigrateOldLogsToLogDB = oldAutoMigrate
		common.LogMigrationBatchSize = oldBatchSize
		common.UsingSQLite = oldUsingSQLite
		common.UsingPostgreSQL = oldUsingPostgreSQL
		common.UsingMySQL = oldUsingMySQL
		common.LogSqlType = oldLogSQLType
		common.AllowLogMigrationToNonEmptyTarget = oldAllowNonEmptyTarget
		_ = sourceSQLDB.Close()
		_ = targetSQLDB.Close()
	}()

	DB = sourceDB
	LOG_DB = targetDB
	common.AutoMigrateOldLogsToLogDB = true
	common.LogMigrationBatchSize = 1
	common.UsingSQLite = true
	common.UsingPostgreSQL = false
	common.UsingMySQL = false
	common.LogSqlType = common.DatabaseTypeSQLite
	common.AllowLogMigrationToNonEmptyTarget = false

	logs := []Log{
		{Id: 1, UserId: 1, CreatedAt: 1, Type: LogTypeConsume, Content: "a", Username: "u1"},
		{Id: 2, UserId: 2, CreatedAt: 2, Type: LogTypeError, Content: "b", Username: "u2"},
	}
	if err := DB.Create(&logs).Error; err != nil {
		t.Fatalf("failed to seed source logs: %v", err)
	}

	if err := MigrateOldLogsToLogDBIfNeeded(); err != nil {
		t.Fatalf("failed to auto migrate logs: %v", err)
	}

	var sourceCount int64
	if err := DB.Model(&Log{}).Count(&sourceCount).Error; err != nil {
		t.Fatalf("failed to count source logs: %v", err)
	}
	if sourceCount != 0 {
		t.Fatalf("expected source logs to be cleared, got %d", sourceCount)
	}

	var targetLogs []Log
	if err := LOG_DB.Order("id asc").Find(&targetLogs).Error; err != nil {
		t.Fatalf("failed to query target logs: %v", err)
	}
	if len(targetLogs) != len(logs) {
		t.Fatalf("expected %d target logs, got %d", len(logs), len(targetLogs))
	}
	for i, targetLog := range targetLogs {
		if targetLog.Id != logs[i].Id {
			t.Fatalf("expected target log id %d, got %d", logs[i].Id, targetLog.Id)
		}
		if targetLog.Content != logs[i].Content {
			t.Fatalf("expected target log content %q, got %q", logs[i].Content, targetLog.Content)
		}
	}
}
