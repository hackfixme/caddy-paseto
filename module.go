package caddypaseto

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"

	"go.hackfix.me/paseto-cli/xpaseto"
)

func init() {
	caddy.RegisterModule(PasetoAuth{})
}

// PasetoAuth implements PASETO authentication.
type PasetoAuth struct {
	// Key is the key used to verify or decrypt PASETO tokens.
	// It must be the public key if `purpose` is 'public', or the symmetric key if
	// `purpose` is 'local'. It can be specified as either a hex or PEM encoded string.
	Key string `json:"key"`

	// Purpose is the PASETO protocol purpose. It can either be 'local' for
	// shared-key (symmetric) encryption, or 'public' for public-key (asymmetric)
	// signing. The default is 'public'.
	Purpose paseto.Purpose `json:"purpose"`

	// Version is the PASETO protocol version. The default is 4.
	Version paseto.Version `json:"version"`

	// TimeSkewTolerance is the amount of time to allow token claim times (iat,
	// nbf, exp) to be from the current system time to account for clock skew
	// between systems. The default is 30s.
	TimeSkewTolerance time.Duration `json:"time_skew_tolerance"`

	// FromQuery defines a list of HTTP request query string parameter names
	// tokens should be retrieved from.
	//
	// If multiple names are specified, all the corresponding query values will be
	// treated as candidate tokens, and each one will be verified until a valid
	// one is reached.
	//
	// Priority: from_query > from_header > from_cookies.
	FromQuery []string `json:"from_query"`

	// FromHeader works like FromQuery, but defines a list of HTTP header names
	// tokens should be retrieved from.
	FromHeader []string `json:"from_header"`

	// FromCookie works like FromQuery, but defines a list of HTTP cookie names
	// tokens should be retrieved from.
	FromCookies []string `json:"from_cookies"`

	// UserClaims defines a list of token claim names from which to extract the ID
	// of the authenticated user.
	//
	// By default, this value will be set to []string{"sub"}.
	//
	// If multiple names are specified, the first non-empty value of the claim in
	// the token payload will be used as the ID of the authenticated user, and the
	// placeholder `{http.auth.user.id}` will be set to the ID. For example, the
	// value `uid username` will set "eva" as the final user ID from the token
	// payload: `{ "username": "eva" }`.
	//
	// If no non-empty values are found, the request fails authentication.
	UserClaims []string `json:"user_claims"`

	// MetaClaims defines a map to populate {http.auth.user.*} metadata placeholders.
	// The key is the claim in the token payload, the value is the placeholder name.
	// e.g. {"IsAdmin": "is_admin"} can populate {http.auth.user.is_admin} with
	// the value of `IsAdmin` in the token payload if found, otherwise "".
	//
	// NOTE: The name in the placeholder should adhere to Caddy conventions
	// (snake casing).
	//
	// Caddyfile:
	// Use syntax `<claim>[-> <placeholder>]` to define a map item. The placeholder is
	// optional, if not specified, use the same name as the claim.
	// E.g.:
	//
	//     meta_claims "IsAdmin -> is_admin" "group"
	//
	// is equal to {"IsAdmin": "is_admin", "group": "group"}.
	//
	// Nested claim paths are supported with dot notation. So for the following
	// token payload:
	//
	//     { ..., "user_info": { "role": "admin" }}
	//
	// If you want to populate {http.auth.user.role} with "admin", you can use
	//
	//     meta_claims "user_info.role -> role"
	MetaClaims map[string]string `json:"meta_claims"`

	// AllowAudiences defines a list of allowed audiences. If non-empty, the "aud"
	// claim must exist in the token payload and its value must be specified here
	// for verification to succeed. Otherwise, the "aud" claim is not required,
	// and any value will be allowed.
	AllowAudiences []string `json:"allow_audiences"`

	// AllowIssuers defines a list of allowed issuers. If non-empty, the "iss"
	// claim must exist in the token payload and its value must be specified here
	// for verification to succeed. Otherwise, the "iss" claim is not required,
	// and any value will be allowed.
	AllowIssuers []string `json:"allow_issuers"`

	// AllowUsers defines a list of allowed users. If non-empty, and the user
	// claim is defined in the token payload, only specified users will pass the
	// verification. Otherwise, all users will be allowed.
	AllowUsers []string `json:"allow_users"`

	// The parsed and decoded key, if validation succeeds.
	key    *xpaseto.Key
	logger *slog.Logger
}

var (
	_ caddy.Provisioner       = (*PasetoAuth)(nil)
	_ caddy.Validator         = (*PasetoAuth)(nil)
	_ caddyauth.Authenticator = (*PasetoAuth)(nil)
)

// CaddyModule returns the Caddy module information.
func (PasetoAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.paseto",
		New: func() caddy.Module { return new(PasetoAuth) },
	}
}

// Provision sets up the module.
func (p *PasetoAuth) Provision(ctx caddy.Context) error {
	p.logger = ctx.Slogger()
	return nil
}

// Validate validates that the module has a usable config, and initializes
// defaults and internal values.
func (p *PasetoAuth) Validate() error {
	if p.Version == "" {
		p.Version = paseto.Version4
	} else if !slices.Contains([]paseto.Version{paseto.Version2, paseto.Version3, paseto.Version4}, p.Version) {
		return fmt.Errorf("invalid version: '%s'", p.Version)
	}

	if p.Purpose == "" {
		p.Purpose = paseto.Public
	} else if !slices.Contains([]paseto.Purpose{paseto.Local, paseto.Public}, p.Purpose) {
		return fmt.Errorf("invalid purpose: '%s'", p.Purpose)
	}

	if p.TimeSkewTolerance == 0 {
		p.TimeSkewTolerance = 30 * time.Second
	}

	if len(p.UserClaims) == 0 {
		p.UserClaims = []string{"sub"}
	}

	var err error
	p.key, err = xpaseto.LoadKey([]byte(p.Key), p.Version, p.Purpose, xpaseto.KeyTypePublic)
	if err != nil {
		//nolint:wrapcheck // the xpaseto error is descriptive enough
		return err
	}

	return nil
}

// Authenticate extracts the token according to the module configuration, parses
// and validates it, and authenticates the user of the request.
func (p *PasetoAuth) Authenticate(_ http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	var candidates []string
	candidates = append(candidates, getTokensFromQuery(r, p.FromQuery)...)
	candidates = append(candidates, getTokensFromHeader(r, p.FromHeader)...)
	candidates = append(candidates, getTokensFromCookies(r, p.FromCookies)...)
	candidates = append(candidates, getTokensFromHeader(r, []string{"Authorization"})...)

	extraValidRules := []paseto.Rule{}
	if len(p.AllowAudiences) > 0 {
		extraValidRules = append(extraValidRules, xpaseto.AllowAudiences(p.AllowAudiences))
	}
	if len(p.AllowIssuers) > 0 {
		extraValidRules = append(extraValidRules, xpaseto.AllowIssuers(p.AllowIssuers))
	}

	checked := make(map[string]struct{})
	for _, candidateToken := range candidates {
		tokenStr := normToken(candidateToken)
		if _, ok := checked[tokenStr]; ok {
			continue
		}

		token, err := xpaseto.ParseToken(p.key, tokenStr)
		checked[tokenStr] = struct{}{}
		logger := p.logger.With("token", maskToken(tokenStr))

		if err != nil {
			logger.Warn(err.Error())
			continue
		}

		err = token.Validate(time.Now, p.TimeSkewTolerance, extraValidRules...)
		if err != nil {
			logger.Warn(err.Error())
			continue
		}

		claimName, userID := getUserID(token.ClaimsRaw(), p.UserClaims)
		if userID == "" {
			logger.Warn("user claim is empty", "user_claims", p.UserClaims)
			continue
		}

		if len(p.AllowUsers) > 0 && !slices.Contains(p.AllowUsers, userID) {
			logger.Warn("user is not allowed", "user_id", userID)
			continue
		}

		user := caddyauth.User{
			ID:       userID,
			Metadata: getUserMetadata(token, p.MetaClaims),
		}

		logger.Info("user authenticated", "user_claim", claimName, "user_id", userID)

		return user, true, nil
	}

	return caddyauth.User{}, false, nil
}
