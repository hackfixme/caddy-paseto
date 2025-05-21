package caddypaseto

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.hackfix.me/caddy-paseto/testutil"
)

func TestPasetoAuth_Authenticate(t *testing.T) {
	v4PrivateKey := paseto.NewV4AsymmetricSecretKey()
	v4PublicKey := v4PrivateKey.Public()

	validToken := paseto.NewToken()
	validToken.SetNotBefore(time.Now())
	validToken.SetExpiration(time.Now().Add(time.Hour))
	validToken.SetSubject("user123")
	validToken.SetAudience("aud123")
	validToken.SetIssuer("test")
	validToken.SetIssuedAt(time.Now())
	validTokenStr := validToken.V4Sign(v4PrivateKey, nil)

	expiredToken := paseto.NewToken()
	expiredToken.SetSubject("user456")
	expiredToken.SetIssuedAt(time.Now().Add(-2 * time.Hour))
	expiredToken.SetNotBefore(time.Now().Add(-2 * time.Hour))
	expiredToken.SetExpiration(time.Now().Add(-time.Hour))
	expiredTokenStr := expiredToken.V4Sign(v4PrivateKey, nil)

	noUserToken := paseto.NewToken()
	noUserToken.SetIssuer("test")
	noUserToken.SetIssuedAt(time.Now())
	noUserToken.SetNotBefore(time.Now())
	noUserToken.SetExpiration(time.Now().Add(time.Hour))
	noUserTokenStr := noUserToken.V4Sign(v4PrivateKey, nil)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		allowAud       []string
		allowIss       []string
		allowUser      []string
		expectAuth     bool
		expectedUserID string
		expErr         string
	}{
		{
			name: "ok/token_in_query",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/?token="+validTokenStr, nil)
			},
			expectAuth:     true,
			expectedUserID: "user123",
		},
		{
			name: "ok/token_in_header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Token", validTokenStr)
				return req
			},
			expectAuth:     true,
			expectedUserID: "user123",
		},
		{
			name: "ok/token_in_cookie",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{
					Name:  "auth",
					Value: validTokenStr,
				})
				return req
			},
			expectAuth:     true,
			expectedUserID: "user123",
		},
		{
			name: "ok/token_in_authorization_header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", "Bearer "+validTokenStr)
				return req
			},
			expectAuth:     true,
			expectedUserID: "user123",
		},
		{
			name: "ok/duplicate_tokens_ignored",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/?token="+validTokenStr, nil)
				req.Header.Set("X-Token", validTokenStr) // Same token in header
				return req
			},
			expectAuth:     true,
			expectedUserID: "user123",
		},
		{
			name: "err/no_token_provided",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/", nil)
			},
			expectAuth: false,
		},
		{
			name: "err/expired_token",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/?token="+expiredTokenStr, nil)
			},
			expectAuth: false,
		},
		{
			name: "err/no_user_claims",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/?token="+noUserTokenStr, nil)
			},
			expectAuth: false,
		},
		{
			name: "err/invalid_token_format",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/?token=invalid-token", nil)
			},
			expectAuth: false,
		},
		{
			name:     "err/blocked_aud",
			allowAud: []string{"aud456"},
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/?token="+validTokenStr, nil)
			},
			expectAuth: false,
		},
		{
			name:     "err/blocked_iss",
			allowIss: []string{"test123"},
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/?token="+validTokenStr, nil)
			},
			expectAuth: false,
		},
		{
			name:      "err/blocked_user",
			allowUser: []string{"user456"},
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/?token="+validTokenStr, nil)
			},
			expectAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &PasetoAuth{
				Key:               v4PublicKey.ExportHex(),
				Version:           paseto.Version4,
				Purpose:           paseto.Public,
				TimeSkewTolerance: 30 * time.Second,
				UserClaims:        []string{"sub"},
				FromQuery:         []string{"token"},
				FromHeader:        []string{"X-Token"},
				FromCookies:       []string{"auth"},
				MetaClaims:        map[string]string{"iss": "issuer"},
				AllowAudiences:    tt.allowAud,
				AllowIssuers:      tt.allowIss,
				AllowUsers:        tt.allowUser,
				logger:            slog.New(testutil.NewTestLogHandler()),
			}
			require.NoError(t, auth.Validate())

			w := httptest.NewRecorder()
			req := tt.setupRequest()
			user, authenticated, err := auth.Authenticate(w, req)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectAuth, authenticated)

			if tt.expectAuth {
				assert.Equal(t, tt.expectedUserID, user.ID)
				assert.NotNil(t, user.Metadata)
				if len(auth.MetaClaims) > 0 {
					assert.Contains(t, user.Metadata, "issuer")
				}
			} else {
				assert.Empty(t, user.ID)
			}
		})
	}
}

func TestPasetoAuth_Validate(t *testing.T) {
	v4PrivateKey := paseto.NewV4AsymmetricSecretKey()
	v4PublicKey := v4PrivateKey.Public()
	v4SymmetricKey := paseto.NewV4SymmetricKey()

	tests := []struct {
		name   string
		config PasetoAuth
		expErr string
	}{
		{
			name: "ok/valid_public_key_v4",
			config: PasetoAuth{
				Key:     v4PublicKey.ExportHex(),
				Version: paseto.Version4,
				Purpose: paseto.Public,
			},
		},
		{
			name: "ok/valid_symmetric_key_v4_local",
			config: PasetoAuth{
				Key:     v4SymmetricKey.ExportHex(),
				Version: paseto.Version4,
				Purpose: paseto.Local,
			},
		},
		{
			name: "ok/defaults_applied",
			config: PasetoAuth{
				Key: v4PublicKey.ExportHex(),
			},
		},
		{
			name: "err/invalid_version",
			config: PasetoAuth{
				Key:     v4PublicKey.ExportHex(),
				Version: "v5",
				Purpose: paseto.Public,
			},
			expErr: "invalid version: 'v5'",
		},
		{
			name: "err/invalid_purpose",
			config: PasetoAuth{
				Key:     v4PublicKey.ExportHex(),
				Version: paseto.Version4,
				Purpose: "invalid",
			},
			expErr: "invalid purpose: 'invalid'",
		},
		{
			name: "err/invalid_key",
			config: PasetoAuth{
				Key:     "invalid-key",
				Version: paseto.Version4,
				Purpose: paseto.Public,
			},
			expErr: "invalid byte",
		},
		{
			name: "err/empty_key",
			config: PasetoAuth{
				Version: paseto.Version4,
				Purpose: paseto.Public,
			},
			expErr: "key length incorrect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				return
			}

			require.NoError(t, err)

			if tt.name == "ok/defaults_applied" {
				assert.Equal(t, paseto.Version4, tt.config.Version)
				assert.Equal(t, paseto.Public, tt.config.Purpose)
			}

			assert.Equal(t, 30*time.Second, tt.config.TimeSkewTolerance)
			assert.Equal(t, []string{"sub"}, tt.config.UserClaims)
			assert.NotNil(t, tt.config.key)
		})
	}
}
