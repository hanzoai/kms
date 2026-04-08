package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/base/core"
)

var (
	ErrMemberNotFound = errors.New("store: member not found")
	ErrMemberExists   = errors.New("store: member already exists")
)

const membersCollection = "kms_members"

// Member holds a member's wrapped CEK for an org.
type Member struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	MemberID   string `json:"member_id"`
	PubKey     string `json:"pub_key"`
	WrappedCEK string `json:"wrapped_cek"`
}

// MemberStore provides CRUD for org members.
type MemberStore struct {
	app core.App
}

// NewMemberStore creates a member store backed by Base.
func NewMemberStore(app core.App) *MemberStore {
	return &MemberStore{app: app}
}

// Create stores a new member record.
func (s *MemberStore) Create(m *Member) error {
	col, err := s.app.FindCollectionByNameOrId(membersCollection)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	rec := core.NewRecord(col)
	rec.Set("org_id", m.OrgID)
	rec.Set("member_id", m.MemberID)
	rec.Set("pub_key", m.PubKey)
	rec.Set("wrapped_cek", m.WrappedCEK)
	if err := s.app.Save(rec); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrMemberExists
		}
		return fmt.Errorf("store: save member: %w", err)
	}
	m.ID = rec.Id
	return nil
}

// Get retrieves a member by org and member ID.
func (s *MemberStore) Get(orgID, memberID string) (*Member, error) {
	rec, err := s.app.FindFirstRecordByFilter(
		membersCollection,
		"org_id = {:org} && member_id = {:mid}",
		map[string]any{"org": orgID, "mid": memberID},
	)
	if err != nil {
		return nil, ErrMemberNotFound
	}
	return recordToMember(rec), nil
}

// List returns all members for an org.
func (s *MemberStore) List(orgID string) ([]*Member, error) {
	records, err := s.app.FindRecordsByFilter(
		membersCollection,
		"org_id = {:org}",
		"", 0, 0,
		map[string]any{"org": orgID},
	)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: list members: %w", err)
	}
	out := make([]*Member, 0, len(records))
	for _, r := range records {
		out = append(out, recordToMember(r))
	}
	return out, nil
}

// Delete removes a member record.
func (s *MemberStore) Delete(orgID, memberID string) error {
	rec, err := s.app.FindFirstRecordByFilter(
		membersCollection,
		"org_id = {:org} && member_id = {:mid}",
		map[string]any{"org": orgID, "mid": memberID},
	)
	if err != nil {
		return ErrMemberNotFound
	}
	return s.app.Delete(rec)
}

func recordToMember(r *core.Record) *Member {
	return &Member{
		ID:         r.Id,
		OrgID:      r.GetString("org_id"),
		MemberID:   r.GetString("member_id"),
		PubKey:     r.GetString("pub_key"),
		WrappedCEK: r.GetString("wrapped_cek"),
	}
}
