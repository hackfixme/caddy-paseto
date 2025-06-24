package xpaseto

import (
	"fmt"
	"slices"
	"time"

	"aidanwoods.dev/go-paseto"
)

// Claim represents a token claim with a code, human-readable name, and value.
type Claim struct {
	Code  string
	Name  string
	Value any
}

// NewClaim creates a new claim with the specified code, name, and value.
func NewClaim(code, name string, value any) Claim {
	return Claim{
		Code:  code,
		Name:  name,
		Value: value,
	}
}

// ClaimAudience creates an audience claim with the specified value.
func ClaimAudience(aud string) Claim {
	return NewClaim("aud", "Audience", aud)
}

// ClaimExpiration creates an expiration claim with the specified time.
func ClaimExpiration(t time.Time) Claim {
	return NewClaim("exp", "Expiration", t)
}

// ClaimID creates an ID claim with the specified value.
func ClaimID(id string) Claim {
	return NewClaim("jti", "ID", id)
}

// ClaimIssuedAt creates an issued at claim with the specified time.
func ClaimIssuedAt(t time.Time) Claim {
	return NewClaim("iat", "Issued At", t)
}

// ClaimIssuer creates an issuer claim with the specified value.
func ClaimIssuer(iss string) Claim {
	return NewClaim("iss", "Issuer", iss)
}

// ClaimNotBefore creates a not before claim with the specified time.
func ClaimNotBefore(t time.Time) Claim {
	return NewClaim("nbf", "Not Before", t)
}

// ClaimSubject creates a subject claim with the specified value.
func ClaimSubject(sub string) Claim {
	return NewClaim("sub", "Subject", sub)
}

// ClaimTimeConsistency checks that the "iat", "nbf", and "exp" fields exist and
// are valid, and that their times are consistent with each other.
// Specifically it checks that iat <= nbf <= exp.
func ClaimTimeConsistency() paseto.Rule {
	return func(token paseto.Token) error {
		iat, err := token.GetIssuedAt()
		if err != nil {
			//nolint:wrapcheck // It doesn't matter. The error is wrapped in Validate.
			return err
		}

		nbf, err := token.GetNotBefore()
		if err != nil {
			//nolint:wrapcheck // It doesn't matter. The error is wrapped in Validate.
			return err
		}

		exp, err := token.GetExpiration()
		if err != nil {
			//nolint:wrapcheck // It doesn't matter. The error is wrapped in Validate.
			return err
		}

		if iat.After(exp) {
			//nolint:staticcheck // ST1005; deliberate capitalization of claim name.
			return fmt.Errorf("Issued At time is after Expiration time")
		}

		if iat.After(nbf) {
			//nolint:staticcheck // ST1005; deliberate capitalization of claim name.
			return fmt.Errorf("Issued At time is after Not Before time")
		}

		if nbf.After(exp) {
			//nolint:staticcheck // ST1005; deliberate capitalization of claim name.
			return fmt.Errorf("Not Before time is after Expiration time")
		}

		return nil
	}
}

// NotBeforeNbf checks that the token has a valid "nbf" field, and that its time
// is before the given time. This is the same rule as paseto.NotBeforeNbf, just
// with a time argument.
func NotBeforeNbf(t time.Time, tolerance time.Duration) paseto.Rule {
	return func(token paseto.Token) error {
		nbf, err := token.GetNotBefore()
		if err != nil {
			return err
		}

		if t.Before(nbf.Add(-tolerance)) {
			return fmt.Errorf("this token is not valid yet")
		}

		return nil
	}
}

// NotExpired checks that the token has a valid "exp" field, and that its time
// is after the given time. This is the same rule as paseto.NotExpired, just
// with a time argument.
func NotExpired(t time.Time, tolerance time.Duration) paseto.Rule {
	return func(token paseto.Token) error {
		exp, err := token.GetExpiration()
		if err != nil {
			return err
		}

		if t.After(exp.Add(tolerance)) {
			return fmt.Errorf("this token has expired")
		}

		return nil
	}
}

// NotIssuedAfter checks that the token has a valid "iat" field, and that its
// time is before the given time. This is a subset of the paseto.ValidAt rule.
func NotIssuedAfter(t time.Time, tolerance time.Duration) paseto.Rule {
	return func(token paseto.Token) error {
		iat, err := token.GetIssuedAt()
		if err != nil {
			return err
		}

		if t.Before(iat.Add(-tolerance)) {
			return fmt.Errorf("this token has a future Issued At time")
		}

		return nil
	}
}

// AllowAudiences checks that the token has a valid "aud" field, and that its
// value is contained in auds.
func AllowAudiences(auds []string) paseto.Rule {
	return func(token paseto.Token) error {
		aud, err := token.GetAudience()
		if err != nil {
			return err
		}

		if !slices.Contains(auds, aud) {
			return fmt.Errorf("audience '%s' is not allowed", aud)
		}

		return nil
	}
}

// AllowIssuers checks that the token has a valid "iss" field, and that its
// value is contained in issuers.
func AllowIssuers(issuers []string) paseto.Rule {
	return func(token paseto.Token) error {
		iss, err := token.GetIssuer()
		if err != nil {
			return err
		}

		if !slices.Contains(issuers, iss) {
			return fmt.Errorf("issuer '%s' is not allowed", iss)
		}

		return nil
	}
}

// AllowSubjects checks that the token has a valid "sub" field, and that its
// value is contained in subs.
func AllowSubjects(subs []string) paseto.Rule {
	return func(token paseto.Token) error {
		sub, err := token.GetSubject()
		if err != nil {
			//nolint:wrapcheck // It doesn't matter. The error is wrapped in Validate.
			return err
		}

		if !slices.Contains(subs, sub) {
			return fmt.Errorf("subject '%s' is not allowed", sub)
		}

		return nil
	}
}

//nolint:gochecknoglobals // Deliberate cache.
var registeredClaims = []Claim{
	ClaimID(""),
	ClaimIssuedAt(time.Time{}),
	ClaimNotBefore(time.Time{}),
	ClaimExpiration(time.Time{}),
	ClaimIssuer(""),
	ClaimSubject(""),
	ClaimAudience(""),
}

// RegisteredClaims returns the registered claims with empty values.
func RegisteredClaims() []Claim {
	return registeredClaims
}
