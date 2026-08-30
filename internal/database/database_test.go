package database

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/database/repository"
)

func TestSQLiteDataPersistsAcrossConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maigo.db")
	db, err := NewConnection(path)
	require.NoError(t, err)

	created, err := repository.NewURLRepository(db).Create(context.Background(), "persist", "https://example.com", nil)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	reopened, err := NewConnection(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.Close()) }()

	found, err := repository.NewURLRepository(reopened).GetByID(context.Background(), created.ID)
	require.NoError(t, err)
	require.Equal(t, "persist", found.ShortCode)
	require.Equal(t, "https://example.com", found.TargetURL)
}
