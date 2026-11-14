package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// literals devuelve las plantillas literales pasadas a M(...) y a c.add(...) (título/detalle/solución).
func literals(t *testing.T) []string {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	lit := func(e ast.Expr) {
		if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
			s, _ := strconv.Unquote(b.Value)
			if s != "" {
				set[s] = true
			}
		}
	}
	for _, p := range pkgs {
		for _, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					if fn.Name == "M" && len(call.Args) > 0 {
						lit(call.Args[0])
					}
				case *ast.SelectorExpr:
					if fn.Sel.Name == "add" && len(call.Args) == 5 {
						lit(call.Args[2])
						lit(call.Args[3])
						lit(call.Args[4])
					}
				}
				return true
			})
		}
	}
	var out []string
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// TestAllMessagesTranslated garantiza que no quede ningún mensaje sin traducción al español.
// Comandos de shell puros: se muestran igual en ambos idiomas.
var commands = map[string]bool{
	"PermitEmptyPasswords no": true, "apt install fail2ban && systemctl enable --now fail2ban": true,
	"apt install trivy  (or https://trivy.dev)": true, "apt update": true, "apt update && apt upgrade": true,
	"chmod 1777 /tmp": true, "dnf upgrade --security": true,
	"fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile": true,
	"find /var/www -type f -perm -o+w -exec chmod o-w {} +":                                    true, "nginx: location ~ /\\.git { deny all; }": true,
	"ps aux --sort=-%mem | head": true, "timedatectl set-ntp true": true,
	"ufw default deny incoming && ufw allow 22 && ufw allow 80,443/tcp && ufw enable": true,
}

func TestAllMessagesTranslated(t *testing.T) {
	for _, s := range literals(t) {
		if commands[s] {
			continue
		}
		if _, ok := es[s]; !ok {
			t.Errorf("sin traducción al español: %q", s)
		}
	}
}
