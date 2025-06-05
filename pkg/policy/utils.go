// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

// JoinPath returns a joined path from a and b.
func JoinPath(a, b string) string {
	return a + labels.PathDelimiter + b
}

// MakeKeyFromIdentitySet takes a set of Identities (map[Identity]struct{})
// and returns a canonical string key
func MakeKeyFromIdentitySet(set map[identity.NumericIdentity]struct{}) string {
	if len(set) == 0 {
		return ""
	}

	ids := make([]int, 0, len(set))
	for id := range set {
		ids = append(ids, int(id))
	}

	sort.Ints(ids) // ensure deterministic order

	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = strconv.Itoa(id)
	}

	return strings.Join(strs, ",")
}

// ParseIdentityKey takes a string key and returns a map of Identity to struct{}.
func ParseIdentityKey(key string) (map[identity.NumericIdentity]struct{}, error) {
	result := make(map[identity.NumericIdentity]struct{})
	if key == "" {
		return result, nil
	}

	parts := strings.Split(key, ",")
	for _, part := range parts {
		num, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		result[identity.NumericIdentity(num)] = struct{}{}
	}

	return result, nil
}
