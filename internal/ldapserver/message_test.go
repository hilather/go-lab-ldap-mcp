package ldapserver

import "testing"

func TestOperationOpCodes(t *testing.T) {
	t.Parallel()
	// Every wire operation maps to its RFC 4511 protocolOp tag; the slice
	// doubles as a compile-time Operation satisfaction check.
	ops := []struct {
		op   Operation
		want OpCode
	}{
		{&BindRequest{}, OpBindRequest},
		{&BindResponse{}, OpBindResponse},
		{&UnbindRequest{}, OpUnbindRequest},
		{&SearchRequest{}, OpSearchRequest},
		{&SearchResultEntry{}, OpSearchResultEntry},
		{&SearchResultDone{}, OpSearchResultDone},
		{&ModifyRequest{}, OpModifyRequest},
		{&ModifyResponse{}, OpModifyResponse},
		{&AddRequest{}, OpAddRequest},
		{&AddResponse{}, OpAddResponse},
		{&DeleteRequest{}, OpDeleteRequest},
		{&DeleteResponse{}, OpDeleteResponse},
		{&ModifyDNRequest{}, OpModifyDNRequest},
		{&ModifyDNResponse{}, OpModifyDNResponse},
		{&CompareRequest{}, OpCompareRequest},
		{&CompareResponse{}, OpCompareResponse},
		{&AbandonRequest{}, OpAbandonRequest},
		{&ExtendedRequest{}, OpExtendedRequest},
		{&ExtendedResponse{}, OpExtendedResponse},
	}
	seen := map[OpCode]bool{}
	for _, tc := range ops {
		if got := tc.op.OpCode(); got != tc.want {
			t.Errorf("%T.OpCode() = %d, want %d", tc.op, got, tc.want)
		}
		if seen[tc.want] {
			t.Errorf("duplicate opcode %d", tc.want)
		}
		seen[tc.want] = true
	}
}

func TestResultCodeString(t *testing.T) {
	t.Parallel()
	cases := map[ResultCode]string{
		ResultSuccess:                      "success",
		ResultInvalidCredentials:           "invalidCredentials",
		ResultNoSuchObject:                 "noSuchObject",
		ResultEntryAlreadyExists:           "entryAlreadyExists",
		ResultUnavailableCriticalExtension: "unavailableCriticalExtension",
		ResultAssertionFailed:              "assertionFailed",
		ResultCode(999):                    "unknownResultCode",
	}
	for code, want := range cases {
		if got := code.String(); got != want {
			t.Errorf("ResultCode(%d).String() = %q, want %q", int(code), got, want)
		}
	}
}

func TestFilterNodes(t *testing.T) {
	t.Parallel()
	// The filter tree is a closed set so evaluation can switch exhaustively.
	var filters []Filter = []Filter{
		&FilterAnd{},
		&FilterOr{},
		&FilterNot{},
		&FilterEquality{Attr: "uid", Value: []byte("alice")},
		&FilterSubstrings{Attr: "cn", Initial: []byte("a")},
		&FilterPresent{Attr: "objectClass"},
		&FilterGreaterOrEqual{},
		&FilterLessOrEqual{},
		&FilterApproxMatch{},
	}
	if len(filters) != 9 {
		t.Fatalf("filters = %d", len(filters))
	}
}
