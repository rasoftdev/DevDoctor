package scanner

import (
	"regexp"
	"strconv"
	"strings"
)

type ver [3]int

func cmpVer(a, b ver) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// parseVer devuelve la versión y cuántas partes numéricas se especificaron.
func parseVer(s string) (ver, int) {
	var v ver
	n := 0
	for i, p := range strings.Split(s, ".") {
		if i > 2 {
			break
		}
		x, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		v[i] = x
		n++
	}
	return v, n
}

var tokRe = regexp.MustCompile(`(\^|~>|~|>=|<=|!=|==|>|<|=)?\s*v?([0-9]+(?:\.[0-9*xX]+)*)`)

// satisfies evalúa constraints estilo composer/npm ("^8.1", ">=18 <23", "8.*", "^7.4 || ^8.0").
func satisfies(constraint string, v ver) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == "*" {
		return true
	}
	alts := strings.Split(strings.ReplaceAll(constraint, "||", "|"), "|")
	for _, alt := range alts {
		if satisfiesAlt(alt, v) {
			return true
		}
	}
	return false
}

func satisfiesAlt(alt string, v ver) bool {
	toks := tokRe.FindAllStringSubmatch(alt, -1)
	if len(toks) == 0 {
		return true
	}
	for _, t := range toks {
		op := t[1]
		base, n := parseVer(t[2])
		ok := true
		switch op {
		case ">=":
			ok = cmpVer(v, base) >= 0
		case ">":
			ok = cmpVer(v, base) > 0
		case "<=":
			ok = cmpVer(v, base) <= 0 || prefixEq(v, base, n)
		case "<":
			ok = cmpVer(v, base) < 0
		case "!=":
			ok = !prefixEq(v, base, n)
		case "^":
			up := ver{base[0] + 1}
			if base[0] == 0 {
				up = ver{0, base[1] + 1}
				if n <= 1 {
					up = ver{1}
				}
			}
			ok = cmpVer(v, base) >= 0 && cmpVer(v, up) < 0
		case "~", "~>":
			up := ver{base[0] + 1}
			if n >= 2 {
				up = ver{base[0], base[1] + 1}
				if n == 2 {
					up = ver{base[0] + 1}
				}
			}
			ok = cmpVer(v, base) >= 0 && cmpVer(v, up) < 0
		default: // "=", "==", ""
			ok = prefixEq(v, base, n)
		}
		if !ok {
			return false
		}
	}
	return true
}

func prefixEq(v, base ver, n int) bool {
	if n == 0 {
		return true
	}
	for i := 0; i < n && i < 3; i++ {
		if v[i] != base[i] {
			return false
		}
	}
	return true
}
