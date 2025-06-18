// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/identity"
)

// CachedIdentitiesSelector is implemented by types that hold a set of identities for use as map keys.
// It provides a unique string key and the underlying identity slice.
//
// This is similar to CachedSelector, but without the selector labels. In centralized network policy
// mode we will be totally avoiding selector labels and network policies are notifies with resolved set
// of identities instead of selector labels, and CachedIdentitiesSelector is used to represent that set of
// identities right now this is mainly used in L4Filters to cache PerSelectorPolicies
type CachedIdentitiesSelector interface {
	// String returns a unique string key for this identity set.
	String() string
	// GetIdentities returns the underlying numeric identities.
	GetIdentities() identity.NumericIdentitySlice
	// IsWildcard returns true if this identity set represents the wildcard (any identity).
	IsWildcard() bool
}

// CachedIdentitiesSelectorSlice is a slice of CachedIdentitiesSelectors that can be sorted.
type CachedIdentitiesSelectorSlice []CachedIdentitiesSelector

// MarshalJSON returns the CachedIdentitiesSelectors as a JSON formatted buffer.
func (s CachedIdentitiesSelectorSlice) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString("[")
	buffer.WriteString("[")

	for i, selector := range s {
		buf, err := json.Marshal(selector.String())
		if err != nil {
			return nil, err
		}
		buffer.Write(buf)
		if i < len(s)-1 {
			buffer.WriteString(",")
		}
	}
	buffer.WriteString("]")
	return buffer.Bytes(), nil
}

func (s CachedIdentitiesSelectorSlice) Len() int {
	return len(s)
}

func (s CachedIdentitiesSelectorSlice) Less(i, j int) bool {
	// Sort by string representation for deterministic ordering
	return s[i].String() < s[j].String()
}

func (s CachedIdentitiesSelectorSlice) Swap(i, j int) {
	// Swap the selectors in the slice
	s[i], s[j] = s[j], s[i]
}

// IdentitySelector implements CachedIdentities backed by a slice of numeric identities.
type IdentitySelector struct {
	identities identity.NumericIdentitySlice
	// key caches the string representation of identities
	key string
	// isWildCard indicates if this selector represents the wildcard identity set {0}.
	isWildcard bool
}

// NewIdentitySelector creates a new IdentitySelector for the given identities and caches its string key.
func NewIdentitySelector(ids identity.NumericIdentitySlice) *IdentitySelector {
	// Copy and sort identities to ensure deterministic key
	sortedIds := make(identity.NumericIdentitySlice, len(ids))
	copy(sortedIds, ids)
	sort.Slice(sortedIds, func(i, j int) bool {
		return sortedIds[i] < sortedIds[j]
	})

	parts := make([]string, len(sortedIds))
	for i, id := range sortedIds {
		parts[i] = strconv.Itoa(int(id))
	}
	key := strings.Join(parts, ",")
	return &IdentitySelector{identities: sortedIds, key: key}
}

// String returns the cached unique key for this identity set.
func (is *IdentitySelector) String() string {
	return is.key
}

// GetIdentities returns the underlying numeric identities.
func (is *IdentitySelector) GetIdentities() identity.NumericIdentitySlice {
	return is.identities
}

// IsWildcard returns true if this selector represents the wildcard identity set {0}.
func (is *IdentitySelector) IsWildcard() bool {
	return is.isWildcard
}
