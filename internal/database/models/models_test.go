package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestURLExpiration(t *testing.T) {
	future := time.Now().Add(time.Hour)
	link := URL{ExpiresAt: &future}
	assert.False(t, link.IsExpired())
	assert.NotNil(t, link.TimeUntilExpiry())

	past := time.Now().Add(-time.Hour)
	link.ExpiresAt = &past
	assert.True(t, link.IsExpired())
	assert.Nil(t, link.TimeUntilExpiry())

	link.ExpiresAt = nil
	assert.False(t, link.IsExpired())
	assert.Nil(t, link.TimeUntilExpiry())
}
