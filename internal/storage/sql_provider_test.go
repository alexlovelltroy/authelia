package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

// Mock model struct for OAuth2BlacklistedJTI
type OAuth2BlacklistedJTI struct {
	Signature string
	ExpiresAt time.Time
}

// MockSQLProvider is a mock implementation of SQLProvider for testing purposes
type MockSQLProvider struct {
	db *sql.DB
}

// LoadOAuth2BlacklistedJTI loads an OAuth2.0 blacklisted JTI from the storage provider.
func (p *MockSQLProvider) LoadOAuth2BlacklistedJTI(ctx context.Context, signature string) (blacklistedJTI *OAuth2BlacklistedJTI, err error) {
	blacklistedJTI = &OAuth2BlacklistedJTI{}

	err = p.db.QueryRowContext(ctx, "SELECT signature, expires_at FROM oauth2_blacklisted_jti WHERE signature = ?", signature).Scan(&blacklistedJTI.Signature, &blacklistedJTI.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("error selecting oauth2 blacklisted JTI with signature '%s': %w", signature, err)
	}

	return blacklistedJTI, nil
}

// Test function for LoadOAuth2BlacklistedJTI
func TestLoadOAuth2BlacklistedJTI(t *testing.T) {
	// Initialize the mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	// Create a new MockSQLProvider
	provider := &MockSQLProvider{db: db}

	ctx := context.Background()

	// Create a time that can be reused and compared

	expirationTime := time.Now().Add(time.Hour)

	// Define test cases
	tests := []struct {
		name          string
		setupMock     func()
		signature     string
		expectedJTI   *OAuth2BlacklistedJTI
		expectedError error
	}{
		{
			name: "Success - JTI found",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"signature", "expires_at"}).
					AddRow("signature1", expirationTime)
				mock.ExpectQuery("^SELECT signature, expires_at FROM oauth2_blacklisted_jti WHERE signature = \\?").
					WithArgs("signature1").
					WillReturnRows(rows)
			},
			signature: "signature1",
			expectedJTI: &OAuth2BlacklistedJTI{
				Signature: "signature1",
				ExpiresAt: expirationTime,
			},
			expectedError: nil,
		},
		{
			name: "No Rows Found",
			setupMock: func() {
				mock.ExpectQuery("^SELECT signature, expires_at FROM oauth2_blacklisted_jti WHERE signature = \\?").
					WithArgs("unknown").
					WillReturnError(sql.ErrNoRows)
			},
			signature:     "unknown",
			expectedJTI:   nil,
			expectedError: sql.ErrNoRows,
		},
		{
			name: "Query Error",
			setupMock: func() {
				mock.ExpectQuery("^SELECT signature, expires_at FROM oauth2_blacklisted_jti WHERE signature = \\?").
					WithArgs("signature2").
					WillReturnError(errors.New("query error"))
			},
			signature:     "signature2",
			expectedJTI:   nil,
			expectedError: fmt.Errorf("error selecting oauth2 blacklisted JTI with signature 'signature2': query error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up the mock expectations
			tt.setupMock()

			// Run the function
			jti, err := provider.LoadOAuth2BlacklistedJTI(ctx, tt.signature)

			// Check the result
			assert.Equal(t, tt.expectedJTI, jti)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			// Ensure all expectations are met
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}
