package ldapserver

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Compile-time satisfaction of the pinned interfaces (T-122).
var (
	_ Store     = (*FakeStore)(nil)
	_ Codec     = (*FakeCodec)(nil)
	_ Schema    = (*FakeSchema)(nil)
	_ ACIEngine = (*FakeACI)(nil)
	_ Plugin    = (*FakePlugin)(nil)
)

// StringAttribute builds an Attribute from strings for tests.
func StringAttribute(name string, values ...string) Attribute {
	a := Attribute{Name: name}
	for _, v := range values {
		a.Values = append(a.Values, []byte(v))
	}
	return a
}

// NewEntry builds an Entry from string-valued attributes for tests.
func NewEntry(dn string, attrs ...Attribute) *Entry {
	return &Entry{DN: dn, Attributes: attrs}
}

// FakeStore is an in-memory Store for unit and protocol tests; T-129 keeps
// it available beside the bbolt store. It is a test double, not a directory
// source of truth (ADR-0008 decision 4): Update serializes writers and
// stages a map clone for rollback, but there is no MVCC snapshot isolation
// or crash safety. Entries are copied in and out, so mutating a returned
// Entry never corrupts stored state.
type FakeStore struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	closed  bool
}

// NewFakeStore returns an empty FakeStore.
func NewFakeStore() *FakeStore {
	return &FakeStore{entries: map[string]*Entry{}}
}

// View runs fn under a read lock.
func (s *FakeStore) View(ctx context.Context, fn func(tx ReadTx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return fmt.Errorf("ldapserver fake store view: %w", ErrStoreClosed)
	}
	return fn(fakeTx{entries: s.entries})
}

// Update stages writes on a cloned map and commits them only when fn
// returns nil.
func (s *FakeStore) Update(ctx context.Context, fn func(tx UpdateTx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("ldapserver fake store update: %w", ErrStoreClosed)
	}
	staged := maps.Clone(s.entries)
	if err := fn(fakeTx{entries: staged}); err != nil {
		return err
	}
	s.entries = staged
	return nil
}

// Close marks the store closed; later View/Update calls fail with
// ErrStoreClosed.
func (s *FakeStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func cloneEntry(e *Entry) *Entry {
	if e == nil {
		return nil
	}
	out := &Entry{DN: e.DN, Attributes: make([]Attribute, len(e.Attributes))}
	for i, a := range e.Attributes {
		vals := make([][]byte, len(a.Values))
		for j, v := range a.Values {
			vals[j] = append([]byte(nil), v...)
		}
		out.Attributes[i] = Attribute{Name: a.Name, Values: vals}
	}
	return out
}

type fakeTx struct {
	entries map[string]*Entry
}

var _ UpdateTx = fakeTx{}

func (t fakeTx) Entry(ctx context.Context, dn config.DN) (*Entry, error) {
	e, ok := t.entries[dn.FoldedKey()]
	if !ok {
		return nil, fmt.Errorf("ldapserver fake store entry: %w", ErrNoSuchObject)
	}
	return cloneEntry(e), nil
}

func (t fakeTx) Children(ctx context.Context, dn config.DN) ([]*Entry, error) {
	if _, ok := t.entries[dn.FoldedKey()]; !ok {
		return nil, fmt.Errorf("ldapserver fake store children: %w", ErrNoSuchObject)
	}
	var out []*Entry
	for _, key := range t.sortedKeys() {
		d, err := config.ParseDN(t.entries[key].DN)
		if err != nil {
			continue
		}
		if d.Depth() == dn.Depth()+1 && d.IsDescendantOf(dn) {
			out = append(out, cloneEntry(t.entries[key]))
		}
	}
	return out, nil
}

func (t fakeTx) Subtree(ctx context.Context, dn config.DN) ([]*Entry, error) {
	if _, ok := t.entries[dn.FoldedKey()]; !ok {
		return nil, fmt.Errorf("ldapserver fake store subtree: %w", ErrNoSuchObject)
	}
	var out []*Entry
	for _, key := range t.sortedKeys() {
		d, err := config.ParseDN(t.entries[key].DN)
		if err != nil {
			continue
		}
		if d.Equal(dn) || d.IsDescendantOf(dn) {
			out = append(out, cloneEntry(t.entries[key]))
		}
	}
	return out, nil
}

func (t fakeTx) Add(ctx context.Context, entry *Entry) error {
	d, err := config.ParseDN(entry.DN)
	if err != nil {
		return fmt.Errorf("ldapserver fake store add: %w", err)
	}
	key := d.FoldedKey()
	if _, ok := t.entries[key]; ok {
		return fmt.Errorf("ldapserver fake store add: %w", ErrEntryExists)
	}
	c := cloneEntry(entry)
	c.DN = d.String()
	t.entries[key] = c
	return nil
}

func (t fakeTx) Replace(ctx context.Context, entry *Entry) error {
	d, err := config.ParseDN(entry.DN)
	if err != nil {
		return fmt.Errorf("ldapserver fake store replace: %w", err)
	}
	key := d.FoldedKey()
	if _, ok := t.entries[key]; !ok {
		return fmt.Errorf("ldapserver fake store replace: %w", ErrNoSuchObject)
	}
	c := cloneEntry(entry)
	c.DN = d.String()
	t.entries[key] = c
	return nil
}

func (t fakeTx) Delete(ctx context.Context, dn config.DN) error {
	key := dn.FoldedKey()
	if _, ok := t.entries[key]; !ok {
		return fmt.Errorf("ldapserver fake store delete: %w", ErrNoSuchObject)
	}
	childSuffix := "," + key
	for k := range t.entries {
		if strings.HasSuffix(k, childSuffix) {
			return fmt.Errorf("ldapserver fake store delete: %w", ErrNotLeaf)
		}
	}
	delete(t.entries, key)
	return nil
}

func (t fakeTx) Rename(ctx context.Context, from, to config.DN) error {
	fromKey, toKey := from.FoldedKey(), to.FoldedKey()
	if _, ok := t.entries[fromKey]; !ok {
		return fmt.Errorf("ldapserver fake store rename: %w", ErrNoSuchObject)
	}
	if _, ok := t.entries[toKey]; ok {
		return fmt.Errorf("ldapserver fake store rename: %w", ErrEntryExists)
	}
	type move struct{ oldKey, newKey, newDN string }
	var moves []move
	fromSuffix := "," + fromKey
	for k, e := range t.entries {
		if k != fromKey && !strings.HasSuffix(k, fromSuffix) {
			continue
		}
		// Folded keys and canonical DN strings have equal length (folding
		// only lowercases), so stripping len(fromKey) bytes drops exactly the
		// old base from both forms.
		moves = append(moves, move{
			oldKey: k,
			newKey: k[:len(k)-len(fromKey)] + toKey,
			newDN:  e.DN[:len(e.DN)-len(fromKey)] + to.String(),
		})
	}
	for _, m := range moves {
		if m.newKey == m.oldKey {
			continue
		}
		if _, clash := t.entries[m.newKey]; clash {
			return fmt.Errorf("ldapserver fake store rename: %w", ErrEntryExists)
		}
	}
	for _, m := range moves {
		if m.newKey == m.oldKey {
			continue
		}
		c := cloneEntry(t.entries[m.oldKey])
		c.DN = m.newDN
		delete(t.entries, m.oldKey)
		t.entries[m.newKey] = c
	}
	return nil
}

// sortedKeys keeps reads deterministic for tests.
func (t fakeTx) sortedKeys() []string {
	keys := make([]string, 0, len(t.entries))
	for k := range t.entries {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// FakeCodec is a scripted Codec for dispatch and listener tests. Reads pop a
// queued message (io.EOF when empty); writes are recorded.
type FakeCodec struct {
	mu       sync.Mutex
	pending  []*Message
	readErr  error
	written  []*Message
	writeErr error
	maxPDU   int
}

// NewFakeCodec returns a FakeCodec reporting the default PDU ceiling.
func NewFakeCodec() *FakeCodec {
	return &FakeCodec{maxPDU: DefaultLimits().MaxPDUBytes}
}

// QueueRead appends a message returned by a later ReadMessage.
func (c *FakeCodec) QueueRead(m *Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = append(c.pending, m)
}

// FailReads makes every ReadMessage return err.
func (c *FakeCodec) FailReads(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readErr = err
}

// FailWrites makes every WriteMessage return err.
func (c *FakeCodec) FailWrites(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeErr = err
}

// SetMaxPDUBytes overrides the reported PDU ceiling.
func (c *FakeCodec) SetMaxPDUBytes(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxPDU = n
}

// ReadMessage pops the next queued message.
func (c *FakeCodec) ReadMessage(ctx context.Context, r io.Reader) (*Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return nil, c.readErr
	}
	if len(c.pending) == 0 {
		return nil, io.EOF
	}
	m := c.pending[0]
	c.pending = c.pending[1:]
	return m, nil
}

// WriteMessage records the message.
func (c *FakeCodec) WriteMessage(ctx context.Context, w io.Writer, m *Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	c.written = append(c.written, m)
	return nil
}

// Written returns the recorded outbound messages.
func (c *FakeCodec) Written() []*Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*Message(nil), c.written...)
}

// MaxPDUBytes reports the configured ceiling.
func (c *FakeCodec) MaxPDUBytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxPDU
}

// FakeSchema is a map-backed Schema for tests.
type FakeSchema struct {
	ocs map[string]ObjectClassDef
	ats map[string]AttributeTypeDef
}

// NewFakeSchema indexes the definitions by lowercase name and by OID.
func NewFakeSchema(ocs []ObjectClassDef, ats []AttributeTypeDef) *FakeSchema {
	s := &FakeSchema{
		ocs: map[string]ObjectClassDef{},
		ats: map[string]AttributeTypeDef{},
	}
	for _, oc := range ocs {
		s.ocs[strings.ToLower(oc.Name)] = oc
		if oc.OID != "" {
			s.ocs[oc.OID] = oc
		}
	}
	for _, at := range ats {
		s.ats[strings.ToLower(at.Name)] = at
		if at.OID != "" {
			s.ats[at.OID] = at
		}
	}
	return s
}

// ObjectClass resolves a name or OID case-insensitively.
func (s *FakeSchema) ObjectClass(name string) (ObjectClassDef, bool) {
	oc, ok := s.ocs[strings.ToLower(name)]
	if !ok {
		oc, ok = s.ocs[name]
	}
	return oc, ok
}

// AttributeType resolves a name or OID case-insensitively.
func (s *FakeSchema) AttributeType(name string) (AttributeTypeDef, bool) {
	at, ok := s.ats[strings.ToLower(name)]
	if !ok {
		at, ok = s.ats[name]
	}
	return at, ok
}

// ObjectClasses lists the registered classes without OID duplicates.
func (s *FakeSchema) ObjectClasses() []ObjectClassDef {
	seen := map[string]struct{}{}
	var out []ObjectClassDef
	for _, key := range s.sortedOCKeys() {
		oc := s.ocs[key]
		if _, dup := seen[oc.Name]; dup {
			continue
		}
		seen[oc.Name] = struct{}{}
		out = append(out, oc)
	}
	return out
}

// AttributeTypes lists the registered attribute types without OID
// duplicates.
func (s *FakeSchema) AttributeTypes() []AttributeTypeDef {
	seen := map[string]struct{}{}
	var out []AttributeTypeDef
	for _, key := range s.sortedATKeys() {
		at := s.ats[key]
		if _, dup := seen[at.Name]; dup {
			continue
		}
		seen[at.Name] = struct{}{}
		out = append(out, at)
	}
	return out
}

func (s *FakeSchema) sortedOCKeys() []string {
	keys := make([]string, 0, len(s.ocs))
	for k := range s.ocs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (s *FakeSchema) sortedATKeys() []string {
	keys := make([]string, 0, len(s.ats))
	for k := range s.ats {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// FakeACI is a programmable ACIEngine. It records every check and denies by
// default; set Decide to answer.
type FakeACI struct {
	Decide func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error)

	mu     sync.Mutex
	checks []ACICheck
}

// Allowed records the check, then defers to Decide or denies.
func (f *FakeACI) Allowed(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
	f.mu.Lock()
	f.checks = append(f.checks, check)
	decide := f.Decide
	f.mu.Unlock()
	if decide != nil {
		return decide(ctx, tx, check)
	}
	return false, nil
}

// Checks returns the recorded checks in order.
func (f *FakeACI) Checks() []ACICheck {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ACICheck(nil), f.checks...)
}

// FakePlugin records write events and can inject a commit-aborting error.
type FakePlugin struct {
	// PluginName overrides Name; empty reports "fake".
	PluginName string
	// Err, when non-nil, is returned by AfterWrite to abort the commit.
	Err error

	mu     sync.Mutex
	events []WriteEvent
}

// Name returns the plugin identifier.
func (p *FakePlugin) Name() string {
	if p.PluginName != "" {
		return p.PluginName
	}
	return "fake"
}

// AfterWrite records the event and returns the injected error, if any.
func (p *FakePlugin) AfterWrite(ctx context.Context, tx UpdateTx, ev WriteEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, ev)
	return p.Err
}

// Events returns the recorded write events in order.
func (p *FakePlugin) Events() []WriteEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]WriteEvent(nil), p.events...)
}
