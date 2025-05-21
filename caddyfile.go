package caddypaseto

import (
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("pasetoauth", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile. Syntax:
//
//	pasetoauth [<matcher>] {
//		key <key>
//		version <protocol version>
//		purpose <protocol purpose>
//		time_skew_tolerance <duration>
//		from_query <query string name>...
//		from_header <header name>...
//		from_cookies <cookie name>...
//		user_claims <claim name>...
//		meta_claims <claim name or transform rule>...
//		allow_audiences <audience name>...
//		allow_issuers <issuer name>...
//		allow_users <user name>...
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p PasetoAuth

	for h.Next() {
		for h.NextBlock(0) {
			opt := h.Val()
			switch opt {
			case "allow_audiences":
				p.AllowAudiences = h.RemainingArgs()

			case "allow_issuers":
				p.AllowIssuers = h.RemainingArgs()

			case "allow_users":
				p.AllowUsers = h.RemainingArgs()

			case "from_query":
				p.FromQuery = h.RemainingArgs()

			case "from_header":
				p.FromHeader = h.RemainingArgs()

			case "from_cookies":
				p.FromCookies = h.RemainingArgs()

			case "key":
				if !h.AllArgs(&p.Key) {
					return nil, h.Errf("key is empty")
				}

			case "purpose":
				var purp string
				if !h.AllArgs(&purp) {
					return nil, h.Errf("invalid purpose: %q", purp)
				}
				p.Purpose = paseto.Purpose(purp)

			case "time_skew_tolerance":
				var tst string
				if !h.AllArgs(&tst) {
					return nil, h.Errf("invalid time skew tolerance: %q", tst)
				}
				var err error
				if p.TimeSkewTolerance, err = time.ParseDuration(tst); err != nil {
					return nil, h.Errf("invalid time skew tolerance: %q", tst)
				}

			case "user_claims":
				p.UserClaims = h.RemainingArgs()

			case "meta_claims":
				p.MetaClaims = make(map[string]string)
				for _, metaClaim := range h.RemainingArgs() {
					claim, placeholder, err := parseMetaClaim(metaClaim)
					if err != nil {
						return nil, h.Errf("invalid meta_claims: %w", err)
					}
					if _, ok := p.MetaClaims[claim]; ok {
						return nil, h.Errf("invalid meta_claims: duplicate claim: %s", claim)
					}
					p.MetaClaims[claim] = placeholder
				}

			case "version":
				var ver string
				if !h.AllArgs(&ver) {
					return nil, h.Errf("invalid version: %q", ver)
				}
				if !strings.HasPrefix(ver, "v") {
					ver = fmt.Sprintf("v%s", ver)
				}
				p.Version = paseto.Version(ver)

			default:
				return nil, h.Errf("unrecognized option: %s", opt)
			}
		}
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"paseto": caddyconfig.JSON(p, nil),
		},
	}, nil
}
