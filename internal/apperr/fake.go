package apperr

// Static is a prebuilt error for tests that need a stable *Error value.
func Static(code Code, public string) *Error {
	return New(code, public)
}
