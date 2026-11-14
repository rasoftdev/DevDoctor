package scanner

import "fmt"

// Msg es un mensaje traducible: una plantilla en inglés (idioma canónico, el que ve la terminal)
// más sus argumentos. El dashboard lo recibe ya traducido según el idioma elegido (es.go).
type Msg struct {
	Tpl  string
	Args []any
}

// M crea un mensaje con plantilla fmt (admite %[2]s para reordenar argumentos al traducir).
func M(tpl string, args ...any) Msg { return Msg{Tpl: tpl, Args: args} }

// Render devuelve el mensaje en "en" o "es". Los argumentos que sean Msg se traducen también.
func (m Msg) Render(lang string) string {
	tpl := m.Tpl
	if lang == "es" {
		if t, ok := es[tpl]; ok {
			tpl = t
		}
	}
	if len(m.Args) == 0 {
		return tpl
	}
	args := make([]any, len(m.Args))
	for i, a := range m.Args {
		if sub, ok := a.(Msg); ok {
			args[i] = sub.Render(lang)
		} else {
			args[i] = a
		}
	}
	return fmt.Sprintf(tpl, args...)
}

// msgOf acepta Msg, string literal (se busca tal cual en el diccionario) o nil.
func msgOf(v any) Msg {
	switch x := v.(type) {
	case Msg:
		return x
	case string:
		return Msg{Tpl: x}
	}
	return Msg{}
}
