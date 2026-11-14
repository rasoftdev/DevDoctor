package web

import _ "embed"

// Index es el dashboard (HTML/CSS/JS en un solo archivo, sin dependencias externas).
//
//go:embed index.html
var Index []byte
