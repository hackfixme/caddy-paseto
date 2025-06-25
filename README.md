# caddy-paseto

This is a [Caddy](https://caddyserver.com/) module that implements HTTP authentication using [Platform-Agnostic Security Tokens](https://paseto.io/). It is partly based on [caddy-jwt](https://github.com/ggicci/caddy-jwt).


## Features

- Supports local and public PASETO v2, v3, and v4 keys.
- Token validation with optional time skew tolerance.
- Extract tokens from query string values, headers, and cookies.
- Configurable user and meta claim extraction.
- Allow lists for user, issuer, and audience claims.


## Usage

1. Build a Caddy binary with this module:
   ```sh
   xcaddy build --with go.hackfix.me/caddy-paseto
   ```

2. Use it in your Caddy configuration:
   ```Caddyfile
   {
   	order pasetoauth before basicauth
   }
   
   example.com {
   	pasetoauth {
   		key 1930e37bda12ff798927482b7e4ef7b9c2a3c7f6a3acb08c7ea55a0ec5fb35cd
   		version 4
   		purpose public
   		time_skew_tolerance 1m
   		from_query token
   		from_header X-Api-Token
   		from_cookies user_session
   		allow_users "Alice" "Bob"
   		allow_issuers https://api.example.com
   		allow_audiences https://api.example.io https://learn.example.com
   		user_claims aud uid user_id username login
   		meta_claims "IsAdmin->is_admin" "settings.payout.paypal.enabled->is_paypal_enabled"
   	}
   
   	respond "Hello {http.auth.user.id}!" 200
   }
   ```

3. Run the Caddy server:
   ```sh
   ./caddy run --config Caddyfile
   ```

> [!TIP]
> If you need a simple way to create PASETO keys and tokens, consider using [paseto-cli](https://go.hackfix.me/paseto-cli).


## Documentation

- `key`: The key used to verify or decrypt PASETO tokens. It must be the public key if `purpose` is "public", or the symmetric key if `purpose` is "local". It can be specified as either a hex or PEM encoded string.

- `purpose`: The PASETO protocol purpose. It can either be "local" for shared-key (symmetric) encryption, or "public" for public-key (asymmetric) signing. The default is "public".

- `version`: The PASETO protocol version. Valid values: 2, 3, 4. The default is 4.

- `time_skew_tolerance`: The amount of time to allow token claim times (`iat`, `nbf`, `exp`) to be from the current system time to account for clock skew between systems. The default is 30s.

- `from_query`: A list of HTTP request query string parameter names tokens should be retrieved from. If multiple names are specified, all the corresponding query values will be treated as candidate tokens, and each one will be verified until a valid one is reached. 

  Priority: `from_query` > `from_header` > `from_cookies`.

- `from_header`: Works like `from_query`, but defines a list of HTTP header names tokens should be retrieved from.

- `from_cookies`: Works like `from_query`, but defines a list of HTTP cookie names tokens should be retrieved from.

- `user_claims`: A list of token claim names from which to extract the ID of the authenticated user. By default, this value will be set to "sub".

  If multiple names are specified, the first non-empty value of the claim in the token payload will be used as the ID of the authenticated user, and the placeholder `{http.auth.user.id}` will be set to the ID. For example, the value `uid username` will set "eva" as the final user ID from the token payload: `{ "username": "eva" }`.
  
  If no non-empty values are found, the request fails authentication.

- `meta_claims`: A list of token claim names to populate `{http.auth.user.*}` metadata values.

  Syntax: `<claim>[ -> <placeholder>]`.

  The placeholder is optional, and is used to remap a claim name to a metadata key. If not specified, the metadata key will be the same as the claim name.
  
  **NOTE**: The name in the placeholder should adhere to Caddy conventions (snake casing).

  Examples:
  - `meta_claims group "IsAdmin -> is_admin"`: The value of the `group` claim will be available as `{http.auth.user.group}`, and the value of the `IsAdmin` claim will be available as `{http.auth.user.is_admin}`.
  
  - `meta_claims "user_info.role -> role"`: Nested claim paths are supported with dot notation, so a token with the claim `"user_info": { "role": "admin" }` will set the value of `{http.auth.user.role}` as "admin".
  
- `allow_audience`: A list of allowed audiences. If non-empty, the "aud" claim must exist in the token payload and its value must be specified here for verification to succeed. Otherwise, the "aud" claim is not required, and any value will be allowed.

- `allow_issuers`: A list of allowed issuers. If non-empty, the "iss" claim must exist in the token payload and its value must be specified here for verification to succeed. Otherwise, the "iss" claim is not required, and any value will be allowed.

- `allow_users`: A list of allowed users. If non-empty, and the user claim is defined in the token payload, only specified users will pass the verification. Otherwise, all users will be allowed.


## License

[MIT](/LICENSE)
