package caddypaseto

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.hackfix.me/paseto-cli/xpaseto"
)

func maskToken(token string) string {
	if len(token) <= 6 {
		return token
	}
	mask := min(len(token)/3, 16)
	return token[:mask] + "..." + token[len(token)-mask:]
}

func normToken(token string) string {
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = token[len("bearer "):]
	}
	return strings.TrimSpace(token)
}

func getTokensFromHeader(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	for _, key := range names {
		token := r.Header.Get(key)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func getTokensFromQuery(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	query := r.URL.Query()
	for _, key := range names {
		token := query.Get(key)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func getTokensFromCookies(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	for _, key := range names {
		if ck, err := r.Cookie(key); err == nil && ck.Value != "" {
			tokens = append(tokens, ck.Value)
		}
	}
	return tokens
}

func getUserID(claims map[string]any, names []string) (string, string) {
	for _, name := range names {
		if userClaim, ok := claims[name]; ok {
			switch val := userClaim.(type) {
			case string:
				return name, val
			case float64:
				return name, strconv.FormatFloat(val, 'f', -1, 64)
			}
		}
	}
	return "", ""
}

func getUserMetadata(token *xpaseto.Token, placeholdersMap map[string]string) map[string]string {
	if len(placeholdersMap) == 0 {
		return nil
	}

	claims := token.ClaimsRaw()
	metadata := make(map[string]string)
	for claimName, placeholder := range placeholdersMap {
		claimValue, ok := claims[claimName]

		// Query nested claims.
		if !ok && strings.Contains(claimName, ".") {
			claimValue, ok = queryNested(claims, strings.Split(claimName, "."))
		}
		if !ok {
			metadata[placeholder] = ""
			continue
		}
		metadata[placeholder] = stringify(claimValue)
	}

	return metadata
}

func queryNested(claims map[string]any, path []string) (any, bool) {
	var (
		object = claims
		ok     bool
	)
	for i := range len(path) {
		if object, ok = object[path[i]].(map[string]any); !ok || object == nil {
			return nil, false
		}
	}

	lastKey := path[len(path)-1]
	return object[lastKey], true
}

func stringify(val any) string {
	if val == nil {
		return ""
	}

	switch uv := val.(type) {
	case string:
		return uv
	case bool:
		return strconv.FormatBool(uv)
	case json.Number:
		return uv.String()
	case float64:
		return strconv.FormatFloat(uv, 'f', -1, 64)
	case time.Time:
		return uv.UTC().Format(time.RFC3339Nano)
	}

	if stringer, ok := val.(fmt.Stringer); ok {
		return stringer.String()
	}

	if slice, ok := val.([]any); ok {
		return stringifySlice(slice)
	}

	return ""
}

func stringifySlice(slice []any) string {
	var result []string
	for _, val := range slice {
		result = append(result, stringify(val))
	}
	return strings.Join(result, ",")
}

// parseMetaClaim parses key to get the claim and corresponding placeholder.
// e.g "IsAdmin -> is_admin" as { Claim: "IsAdmin", Placeholder: "is_admin" }.
func parseMetaClaim(key string) (claim, placeholder string, err error) {
	parts := strings.Split(key, "->")
	if len(parts) == 1 {
		claim = strings.TrimSpace(parts[0])
		placeholder = strings.TrimSpace(parts[0])
	} else if len(parts) == 2 {
		claim = strings.TrimSpace(parts[0])
		placeholder = strings.TrimSpace(parts[1])
	} else {
		return "", "", fmt.Errorf("too many delimiters (->) in key %q", key)
	}

	if claim == "" {
		return "", "", fmt.Errorf("empty claim in key %q", key)
	}
	if placeholder == "" {
		return "", "", fmt.Errorf("empty placeholder in key %q", key)
	}
	return
}
