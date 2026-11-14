package notify

import (
	"testing"
	"time"
)

func day(offset int) string { return time.Now().AddDate(0, 0, offset).Format("2006-01-02") }

func TestRecentWindow(t *testing.T) {
	cases := []struct {
		name string
		date string
		days int
		want bool
	}{
		{"sin fecha siempre cuenta", "", 7, true},
		{"sin ventana (todo)", day(-400), 0, true},
		{"hoy, ventana 24 h", day(0), 1, true},
		{"ayer, ventana 24 h", day(-1), 1, true},
		{"hace 3 días, ventana 24 h", day(-3), 1, false},
		{"hace 3 días, ventana semana", day(-3), 7, true},
		{"hace 10 días, ventana semana", day(-10), 7, false},
		{"hace 10 días, ventana mes", day(-10), 31, true},
		{"hace 45 días, ventana mes", day(-45), 31, false},
		{"fecha ilegible cuenta", "no-es-fecha", 7, true},
	}
	for _, c := range cases {
		if got := recent(c.date, c.days); got != c.want {
			t.Errorf("%s: recent(%q, %v) = %v, quería %v", c.name, c.date, c.days, got, c.want)
		}
	}
}

func TestFingerprintIgnoresChangingNumbers(t *testing.T) {
	// los valores que cambian solos (días restantes) no deben generar un problema "nuevo" cada día
	a := numUnit.ReplaceAllString("Certificate expires in 29 days: x", "#$1")
	b := numUnit.ReplaceAllString("Certificate expires in 28 days: x", "#$1")
	if a != b {
		t.Errorf("las huellas deberían coincidir: %q vs %q", a, b)
	}
}
