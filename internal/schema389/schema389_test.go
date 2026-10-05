package schema389

import (
	"os"
	"strings"
	"testing"
)

func TestDataMatchesPinnedImage(t *testing.T) {
	digest, err := os.ReadFile("../../deploy/docker/dirsrv.digest")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Image(), strings.TrimSpace(string(digest)); got != want {
		t.Fatalf("attributetypes.txt is for %q, pinned image is %q: regenerate it (oracle probe 17)", got, want)
	}
	if Count() < 1000 {
		t.Fatalf("only %d attributeTypes", Count())
	}
}

// TestKnownMatchesOracle pins probe 16/19 accept and reject verdicts.
func TestKnownMatchesOracle(t *testing.T) {
	for _, n := range []string{"uid", "UID", "userid", "uid;x-test", "uid;", "uid;;x-test", "2.5.4.4", "2.5.4.4;", "0.9.2342.19200300.100.1.1",
		"pwdReset", "passwordHistory", "pwdUpdateTime", "nsAccountLock", "entryUUID", "memberOf", "aci", "nsUniqueId", "entrydn", "objectClass",
		"telephoneNumber", "mailAlternateAddress", "nsds5ReplicaCredentials", "userCertificate;binary", "cn;lang-en;x-a", "allowWeakCipher-oid", "nsAdminDomainName-oid"} {
		if !Known(n) {
			t.Errorf("%q: 389 accepts it", n)
		}
	}
	for _, n := range []string{"fooBar", "fooBar;x-test", "1.2.3.4", "pwdAccountLockedTime", "pwdChangedTime", "person", "inetOrgPerson", ""} {
		if Known(n) {
			t.Errorf("%q: 389 rejects it", n)
		}
	}
}

func TestPrimary(t *testing.T) {
	for in, want := range map[string]string{
		"pwdHistory":          "passwordHistory",
		"homeTelephoneNumber": "homePhone",
		"fax;lang-en":         "facsimileTelephoneNumber;lang-en",
		"rfc822Mailbox":       "mail",
		"2.5.4.4":             "sn",
		"mail":                "mail",
		"notAnAttribute;x":    "notAnAttribute;x",
	} {
		if got := Primary(in); got != want {
			t.Errorf("Primary(%q) = %q, want %q", in, got, want)
		}
	}
}
