package rdap

import (
	"encoding/json"
	"testing"
)

func TestRegistrationDate(t *testing.T) {
	r := &Result{Found: true, Resp: &Response{
		Events: []Event{{Action: "registration", Date: "1998-03-04T00:00:00Z"}},
	}}
	if got := RegistrationDate(r); got != "1998-03-04" {
		t.Errorf("RegistrationDate = %q", got)
	}
	if got := RegistrationDate(nil); got != "Unknown / Lookup Failed" {
		t.Errorf("nil RegistrationDate = %q", got)
	}
}

func TestRegistrarPrefersRegistrarRole(t *testing.T) {
	mk := func(roles []string, name string) entity {
		props, _ := json.Marshal([]any{[]any{"fn", map[string]any{}, "text", name}})
		inner := json.RawMessage(props)
		tag, _ := json.Marshal("vcard")
		return entity{Roles: roles, VCardArray: []json.RawMessage{tag, inner}}
	}
	r := &Result{Found: true, Resp: &Response{Entities: []entity{
		mk([]string{"registrant"}, "Someone Else"),
		mk([]string{"registrar"}, "MarkMonitor Inc."),
	}}}
	if got := Registrar(r); got != "MarkMonitor Inc." {
		t.Errorf("Registrar = %q", got)
	}
	if got := Registrar(nil); got != "Unknown" {
		t.Errorf("nil Registrar = %q", got)
	}
}
