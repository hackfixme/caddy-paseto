package caddypaseto

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/stretchr/testify/assert"
)

func TestParseCaddyfileOK(t *testing.T) {
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	pasetoauth {
		key "33e9c87f28d6384ee0a113ebe9f4ae5cc75a5c328d62245d5a3af4927ba4778f"
		from_query access_token token _tok
		from_header X-Api-Key
		from_cookies user_session SESSID
		user_claims uid user_id login username
		meta_claims "IsAdmin -> is_admin" "gender"
		allow_issuers https://api.example.com
		allow_audiences https://api.example.io https://learn.example.com
    allow_users testuser
	}
	`),
	}
	expectedPA := &PasetoAuth{
		Key:            "33e9c87f28d6384ee0a113ebe9f4ae5cc75a5c328d62245d5a3af4927ba4778f",
		FromQuery:      []string{"access_token", "token", "_tok"},
		FromHeader:     []string{"X-Api-Key"},
		FromCookies:    []string{"user_session", "SESSID"},
		AllowAudiences: []string{"https://api.example.io", "https://learn.example.com"},
		AllowIssuers:   []string{"https://api.example.com"},
		AllowUsers:     []string{"testuser"},
		UserClaims:     []string{"uid", "user_id", "login", "username"},
		MetaClaims:     map[string]string{"IsAdmin": "is_admin", "gender": "gender"},
	}

	h, err := parseCaddyfile(helper)
	assert.Nil(t, err)
	auth, ok := h.(caddyauth.Authentication)
	assert.True(t, ok)
	jsonConfig, ok := auth.ProvidersRaw["paseto"]
	assert.True(t, ok)
	assert.Equal(t, caddyconfig.JSON(expectedPA, nil), jsonConfig)
}

func TestParseCaddyfileErr(t *testing.T) {
	tests := []struct {
		name           string
		caddyfile      string
		expectedErrMsg string
	}{
		{
			name: "empty_key",
			caddyfile: `
	pasetoauth {
		key
	}
	`,
			expectedErrMsg: "key is empty",
		},
		{
			name: "invalid_meta_claims-parse",
			caddyfile: `
	pasetoauth {
		meta_claims IsAdmin->is_admin->
	}
	`,
			expectedErrMsg: "invalid meta_claims: too many delimiters",
		},
		{
			name: "invalid_meta_claims-duplicate",
			caddyfile: `
	pasetoauth {
		meta_claims IsAdmin->is_admin Gender->gender IsAdmin->admin
	}
	`,
			expectedErrMsg: "invalid meta_claims: duplicate claim",
		},
		{
			name: "unrecognized_option",
			caddyfile: `
	pasetoauth {
		upstream http://192.168.1.4
	}
	`,
			expectedErrMsg: "unrecognized option",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper := httpcaddyfile.Helper{
				Dispenser: caddyfile.NewTestDispenser(tt.caddyfile),
			}

			_, err := parseCaddyfile(helper)
			assert.NotNil(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrMsg)
		})
	}
}

func TestParseMetaClaim(t *testing.T) {
	tests := []struct {
		Key         string
		Claim       string
		Placeholder string
		Pass        bool
	}{
		{"username", "username", "username", true},
		{"registerYear->register_year", "registerYear", "register_year", true},
		{"IsAdmin -> is_admin", "IsAdmin", "is_admin", true},
		{"Gender", "Gender", "Gender", true},
		{"->slot", "", "", false},
		{"IsMember->", "", "", false},
		{"Favorite -> favorite->fav", "", "", false},
	}

	for _, tt := range tests {
		claim, placeholder, err := parseMetaClaim(tt.Key)
		assert.Equal(t, claim, tt.Claim)
		assert.Equal(t, placeholder, tt.Placeholder)
		if tt.Pass == true {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Contains(t, err.Error(), tt.Key)
		}
	}
}
