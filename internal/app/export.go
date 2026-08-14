package app

import (
	"context"
	"io"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// ExportRequest is the transport-neutral GET /api/v1/export query.
// OmitSecrets defaults to true when nil.
type ExportRequest struct {
	OmitSecrets *bool
	MaxEntries  int
	MaxBytes    int64
}

// Export streams a redacted LDIF of the managed suffix (T-083).
type Export struct {
	hooks      hooks
	dir        directory.ResetSupport
	maxEntries int
	maxBytes   int64
	observe    func(outcome string)
}

func (s *Export) Write(ctx context.Context, p Principal, w io.Writer, req ExportRequest) error {
	if s == nil {
		return directory.ExportError("export", directory.FieldUnavailable, "export is not configured")
	}
	if err := s.hooks.authorize(ctx, p, OpExport); err != nil {
		return err
	}
	if err := s.hooks.allowRead(ctx); err != nil {
		return err
	}
	if w == nil {
		s.fail(ctx, p)
		return directory.ExportError("export", directory.FieldUnavailable, "export writer is not configured")
	}
	opts, err := s.resolve(req)
	if err != nil {
		s.fail(ctx, p)
		return err
	}
	if s.dir == nil {
		s.fail(ctx, p)
		return directory.ExportError("export", directory.FieldUnavailable, "export is not configured")
	}
	if err := ctx.Err(); err != nil {
		s.fail(ctx, p)
		return err
	}
	err = s.dir.Export(ctx, w, opts)
	if err != nil {
		s.fail(ctx, p)
		return err
	}
	s.hooks.record(ctx, p, OpExport.Name, "export", AuditSuccess, "", "")
	if s.observe != nil {
		s.observe("success")
	}
	return nil
}

func (s *Export) resolve(req ExportRequest) (directory.ExportOptions, error) {
	omit := true
	if req.OmitSecrets != nil {
		omit = *req.OmitSecrets
	}
	maxE := s.maxEntries
	if maxE <= 0 {
		maxE = 20000
	}
	maxB := s.maxBytes
	if maxB <= 0 {
		maxB = 67108864
	}
	if req.MaxEntries < 0 {
		return directory.ExportOptions{}, apperr.New(apperr.CodeConfiguration, "export maxEntries is invalid").
			WithField(apperr.Field{Path: "maxEntries", Code: "invalid", Message: "maxEntries must be zero or positive"})
	}
	if req.MaxBytes < 0 {
		return directory.ExportOptions{}, apperr.New(apperr.CodeConfiguration, "export maxBytes is invalid").
			WithField(apperr.Field{Path: "maxBytes", Code: "invalid", Message: "maxBytes must be zero or positive"})
	}
	if req.MaxEntries > 0 {
		if req.MaxEntries < maxE {
			maxE = req.MaxEntries
		}
	}
	if req.MaxBytes > 0 {
		if req.MaxBytes < maxB {
			maxB = req.MaxBytes
		}
	}
	return directory.ExportOptions{OmitSecrets: omit, MaxEntries: maxE, MaxBytes: maxB}, nil
}

func (s *Export) fail(ctx context.Context, p Principal) {
	s.hooks.record(ctx, p, OpExport.Name, "export", AuditFailure, "", "")
	if s.observe != nil {
		s.observe("failure")
	}
}
