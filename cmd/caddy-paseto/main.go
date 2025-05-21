package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/logging"

	_ "go.hackfix.me/caddy-paseto"
)

func main() {
	caddycmd.Main()
}
