package agentassets

import "embed"

// Public contains the Nift-built agent interface.
//
//go:embed public/* public/assets/css/* public/assets/js/*
var Public embed.FS
