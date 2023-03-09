package main

import (
	"reflect"
	"testing"
)

func testParseCertSubject(t *testing.T, subject string, expected map[string][]string) {
	result, err := parseCertSubject(subject)
	if err != nil {
		t.Error("got unexpected error: ", err)
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("didn't get expected result: result=%v, expected=%v", result, expected)
	}
}

// examples from https://tools.ietf.org/html/rfc2253
func TestParseCertSubject(t *testing.T) {
	testParseCertSubject(t, `CN=Steve Kille,O=Isode Limited,C=GB`, map[string][]string{
		"CN": {"Steve Kille"},
		"O":  {"Isode Limited"},
		"C":  {"GB"},
	})

	testParseCertSubject(t, `OU=Sales+CN=J. Smith,O=Widget Inc.,C=US`, map[string][]string{
		"OU": {"Sales"},
		"CN": {"J. Smith"},
		"O":  {"Widget Inc."},
		"C":  {"US"},
	})

	testParseCertSubject(t, `CN=L. Eagle,O=Sue\, Grabbit and Runn,C=GB`, map[string][]string{
		"CN": {"L. Eagle"},
		"O":  {"Sue, Grabbit and Runn"},
		"C":  {"GB"},
	})

	testParseCertSubject(t, `CN=Before\0DAfter,O=Test,C=GB`, map[string][]string{
		"CN": {"Before\rAfter"},
		"O":  {"Test"},
		"C":  {"GB"},
	})

	testParseCertSubject(t, `1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB`, map[string][]string{
		"1.3.6.1.4.1.1466.0": {string([]byte{0x04, 0x02, 0x48, 0x69})},
		"O":                  {"Test"},
		"C":                  {"GB"},
	})

	testParseCertSubject(t, `SN=Lu\C4\8Di\C4\87`, map[string][]string{
		"SN": {"Lu\xC4\x8Di\xC4\x87"},
	})
}
