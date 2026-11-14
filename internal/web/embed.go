package web

import "embed"

// Index es el dashboard (HTML/CSS/JS en un solo archivo, sin dependencias externas).
//
//go:embed index.html
var Index []byte

// Assets contiene el logo y los iconos (favicon) que sirve el dashboard.
//
//go:embed logo.png favicon.png favicon-32.png apple-touch-icon.png
var Assets embed.FS
