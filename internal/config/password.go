package config

import (
	"errors"
	"strings"
	"unicode"
)

// Palabras y secuencias que hacen trivial una contraseña corta.
var weakParts = []string{
	"password", "contraseña", "contrasena", "qwerty", "asdfgh", "123456", "654321", "abcdef",
	"admin", "root", "devdoctor", "letmein", "welcome", "changeme", "iloveyou", "passw0rd", "p@ssw0rd",
}

// ValidatePassword aplica la política de contraseñas: 10–128 caracteres, no trivial,
// no basada en el usuario y con variedad (o suficiente longitud como frase).
func ValidatePassword(user, pw string) error {
	n := len([]rune(pw))
	switch {
	case n < 10:
		return errors.New("la contraseña debe tener al menos 10 caracteres")
	case n > 128:
		return errors.New("la contraseña no puede superar 128 caracteres")
	}
	low := strings.ToLower(pw)
	if u := strings.ToLower(strings.TrimSpace(user)); len(u) >= 3 && strings.Contains(low, u) {
		return errors.New("la contraseña no puede contener tu nombre de usuario")
	}
	same := true
	for _, r := range pw {
		if r != []rune(pw)[0] {
			same = false
			break
		}
	}
	if same {
		return errors.New("la contraseña no puede ser un solo carácter repetido")
	}
	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, symbol} {
		if b {
			classes++
		}
	}
	if n < 16 {
		for _, w := range weakParts {
			if strings.Contains(low, w) {
				return errors.New("la contraseña contiene una palabra o secuencia demasiado común; usa una frase más larga (16+ caracteres) o algo menos predecible")
			}
		}
		if classes < 3 {
			return errors.New("mezcla al menos 3 tipos (minúsculas, mayúsculas, números, símbolos) o usa una frase de 16+ caracteres")
		}
	}
	return nil
}
