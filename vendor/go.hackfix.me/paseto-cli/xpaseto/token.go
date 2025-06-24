package xpaseto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"aidanwoods.dev/go-paseto"
)

// TokenFormat represents the output format for token display.
type TokenFormat string

const (
	TokenFormatText TokenFormat = "text"
	TokenFormatJSON TokenFormat = "json"
)

// Token represents a PASETO token with claims.
type Token struct {
	*paseto.Token
}

const defaultExpiration = time.Hour

// NewToken creates a new token with the specified claims.
// Default claims (iat, nbf, exp) are automatically added if not provided.
func NewToken(timeNowFn func() time.Time, claims ...Claim) (*Token, error) {
	token := paseto.NewToken()

	for _, c := range claims {
		switch val := c.Value.(type) {
		case string:
			token.SetString(c.Code, val)
		case time.Time:
			token.SetTime(c.Code, val)
		default:
			if err := token.Set(c.Code, c.Value); err != nil {
				return nil, fmt.Errorf("failed creating new token: %w", err)
			}
		}
	}

	var (
		setClaims = token.Claims()
		timeNow   = timeNowFn()
	)
	if _, ok := setClaims["iat"]; !ok {
		token.SetIssuedAt(timeNow)
	}
	if _, ok := setClaims["nbf"]; !ok {
		token.SetNotBefore(timeNow)
	}
	if _, ok := setClaims["exp"]; !ok {
		token.SetExpiration(timeNow.Add(defaultExpiration))
	}

	return &Token{&token}, nil
}

// ParseToken parses a PASETO token string using the provided key.
func ParseToken(key *Key, token string) (*Token, error) {
	tp, err := TokenProtocol(token)
	if err != nil {
		return nil, fmt.Errorf("failed parsing token: %w", err)
	}
	if tp.Version() != key.version || tp.Purpose() != key.purpose {
		return nil, ErrKeyTokenProtocolMismatch
	}

	var (
		parser = paseto.MakeParser(nil)
		tk     *paseto.Token
	)
	switch key.version {
	case paseto.Version2:
		if key.purpose == paseto.Local {
			tk, err = parser.ParseV2Local(key.key.(paseto.V2SymmetricKey), token)
		} else {
			tk, err = parser.ParseV2Public(key.key.(paseto.V2AsymmetricPublicKey), token)
		}
	case paseto.Version3:
		if key.purpose == paseto.Local {
			tk, err = parser.ParseV3Local(key.key.(paseto.V3SymmetricKey), token, nil)
		} else {
			tk, err = parser.ParseV3Public(key.key.(paseto.V3AsymmetricPublicKey), token, nil)
		}
	case paseto.Version4:
		if key.purpose == paseto.Local {
			tk, err = parser.ParseV4Local(key.key.(paseto.V4SymmetricKey), token, nil)
		} else {
			tk, err = parser.ParseV4Public(key.key.(paseto.V4AsymmetricPublicKey), token, nil)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed parsing token: %w", err)
	}

	return &Token{tk}, nil
}

// Claims returns all claims of this token in a stable order. Registered claims
// will be first in the order defined by RegisteredClaims, followed by custom
// claims ordered lexicographically by name. An error is returned if converting
// a registered claim value to its expected type fails.
func (tk *Token) Claims() ([]Claim, error) {
	rawClaims := tk.ClaimsRaw()
	regClaims := RegisteredClaims()
	claims := make([]Claim, 0, len(rawClaims))

	seenClaims := make(map[string]bool, len(regClaims))
	for _, claim := range regClaims {
		var err error
		if _, ok := claim.Value.(string); ok {
			claim.Value, err = tk.GetString(claim.Code)
		} else {
			claim.Value, err = tk.GetTime(claim.Code)
		}

		if err != nil {
			if strings.Contains(err.Error(), "not present in claims") {
				continue
			}
			return nil, fmt.Errorf("failed getting registered claim '%s': %w", claim.Code, err)
		}

		claims = append(claims, claim)
		seenClaims[claim.Code] = true
	}

	customClaimsNames := make([]string, 0, len(rawClaims)-len(seenClaims))
	for name := range rawClaims {
		if !seenClaims[name] {
			customClaimsNames = append(customClaimsNames, name)
		}
	}
	slices.Sort(customClaimsNames)

	for _, name := range customClaimsNames {
		claim := NewClaim(name, "", rawClaims[name])
		claims = append(claims, claim)
	}

	return claims, nil
}

// ClaimsRaw returns the raw claim data.
func (tk *Token) ClaimsRaw() map[string]any {
	return tk.Token.Claims()
}

// Validate validates the token against default and additional rules.
func (tk *Token) Validate(
	timeNowFn func() time.Time, timeSkewTolerance time.Duration,
	extraRules ...paseto.Rule,
) (err error) {
	timeNow := timeNowFn()
	defaultRules := []paseto.Rule{
		ClaimTimeConsistency(),
		NotIssuedAfter(timeNow, timeSkewTolerance),
		NotBeforeNbf(timeNow, timeSkewTolerance),
		NotExpired(timeNow, timeSkewTolerance),
	}

	rules := append(defaultRules, extraRules...)

	for _, rule := range rules {
		if err = rule(*tk.Token); err != nil {
			return fmt.Errorf("invalid token: %w", err)
		}
	}

	return nil
}

// Write writes the token data to the specified writer in the given format.
//
//nolint:gocognit,nestif // This is fine.
func (tk *Token) Write(w io.Writer, f TokenFormat) error {
	switch f {
	case TokenFormatText:
		tw := tabwriter.NewWriter(w, 6, 2, 2, ' ', 0)

		claims, err := tk.Claims()
		if err != nil {
			return err
		}

		var (
			i     int
			claim Claim
		)
		for i, claim = range claims {
			if claim.Name == "" {
				break
			}
			_, err = fmt.Fprintf(tw, "%s:\t%v\n", claim.Name, claim.Value)
			if err != nil {
				return fmt.Errorf("failed writing token data: %w", err)
			}
		}

		if i < len(claims)-1 {
			_, err = fmt.Fprintf(tw, "\nCustom Claims\n")
			if err != nil {
				return fmt.Errorf("failed writing token data: %w", err)
			}
			_, err = fmt.Fprintf(tw, "-------------\n")
			if err != nil {
				return fmt.Errorf("failed writing token data: %w", err)
			}
			for j := i; j < len(claims); j++ {
				val := claims[j].Value
				if _, ok := val.(map[string]any); ok {
					jsonVal, jsonErr := json.Marshal(val)
					if jsonErr != nil {
						return fmt.Errorf("failed marshaling claim '%s' to JSON: %w", claims[j].Code, err)
					}
					val = string(jsonVal)
				}
				_, err = fmt.Fprintf(tw, "%s:\t%v\n", claims[j].Code, val)
				if err != nil {
					return fmt.Errorf("failed writing token data: %w", err)
				}
			}
		}

		err = tw.Flush()
		if err != nil {
			return fmt.Errorf("failed writing token data: %w", err)
		}
	case TokenFormatJSON:
		m, err := json.MarshalIndent(tk.ClaimsRaw(), "", "  ")
		if err != nil {
			return fmt.Errorf("failed marshaling token data to JSON: %w", err)
		}
		_, err = w.Write(m)
		if err != nil {
			return fmt.Errorf("failed writing token data: %w", err)
		}
	default:
		return fmt.Errorf("invalid token format: %v", f)
	}

	return nil
}

// TokenProtocol determines the PASETO protocol from a token string.
func TokenProtocol(token string) (paseto.Protocol, error) {
	switch {
	case strings.HasPrefix(token, paseto.V4Local.Header()):
		return paseto.V4Local, nil
	case strings.HasPrefix(token, paseto.V4Public.Header()):
		return paseto.V4Public, nil
	case strings.HasPrefix(token, paseto.V3Local.Header()):
		return paseto.V3Local, nil
	case strings.HasPrefix(token, paseto.V3Public.Header()):
		return paseto.V3Public, nil
	case strings.HasPrefix(token, paseto.V2Local.Header()):
		return paseto.V2Local, nil
	case strings.HasPrefix(token, paseto.V2Public.Header()):
		return paseto.V2Public, nil
	}

	return paseto.Protocol{}, errors.New("invalid token header")
}
