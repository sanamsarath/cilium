//go:build !ignore_uncovered
// +build !ignore_uncovered

package v2alpha1

import (
	"github.com/cilium/cilium/pkg/identity"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Important: Run "make" to regenerate code after modifying this file

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=ciliumresolvedpolicies,scope=Cluster,shortName=crp,categories={cilium}
type CiliumResolvedPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of CiliumResolvedPolicy
	Spec CiliumResolvedPolicySpec `json:"spec"`

	// Specs defines the list of resolved policy specs
	Specs []CiliumResolvedPolicySpec `json:"specs,omitempty"`

	// SourcePolicyRef defines the source policy information
	// +kubebuilder:validation:Required
	SourcePolicyRef PolicyRef `json:"sourcePolicyRef"`

	// Status defines the observed state of CiliumResolvedPolicy
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumResolvedPolicyStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// CiliumResolvedPolicyList contains a list of CiliumResolvedPolicy
type CiliumResolvedPolicyList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CiliumResolvedPolicy `json:"items"`
}

// CiliumResolvedPolicySpec defines the desired state of CiliumResolvedPolicy
type CiliumResolvedPolicySpec struct {
	// AppliesTo defines endpoints to which this policy applies
	// +kubebuilder:validation:Required
	AppliesTo AppliesTo `json:"appliesTo"`

	// ResolvedIngressRules defines the ingress rules for this policy
	// +kubebuilder:validation:Optional
	ResolvedIngressRules []ResolvedIngressRule `json:"resolvedIngressRules,omitempty"`

	// ResolvedIngressDenyRules defines the deny ingress rules for this policy
	// +kubebuilder:validation:Optional
	ResolvedIngressDenyRules []ResolvedIngressDenyRule `json:"resolvedIngressDenyRules,omitempty"`

	// ResolvedEgressRules defines the egress rules for this policy
	// +kubebuilder:validation:Optional
	ResolvedEgressRules []ResolvedEgressRule `json:"resolvedEgressRules,omitempty"`

	// ResolvedEgressDenyRules defines the deny egress rules for this policy
	// +kubebuilder:validation:Optional
	ResolvedEgressDenyRules []ResolvedEgressRule `json:"resolvedEgressDenyRules,omitempty"`
}

// CiliumResolvedPolicyStatus defines the observed state of CiliumResolvedPolicy
type CiliumResolvedPolicyStatus struct {
	// LastUpdated represents the time when this policy was last updated
	LastUpdated slimv1.Time `json:"lastUpdated"`
	SyncState   SyncState   `json:"syncState,omitempty"`
}

// PolicyRef contains references to the source policy
type PolicyRef struct {
	// Name is the name of the source policy
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace is the namespace of the source policy
	// If empty, the policy is assumed to be cluster-wide
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace"`

	// Type is the type of the source policy
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=CNP;CCNP;KNP
	Type PolicyType `json:"type"`
}

// AppliesTo defines the set of endpoints to which a policy applies
type AppliesTo struct {
	// Identities is the list of security identities to which this policy applies
	// +kubebuilder:validation:Optional
	Identities identity.NumericIdentitySlice `json:"identities"`

	// CacheSelector is the string representation of the selector used to select identities
	// +kubebuilder:validation:Optional
	CacheSelector string `json:"cacheSelector,omitempty"`
}

// IngressCommonRule is a rule that shares some of its fields across the
// ResolvedIngressRule and ResolvedIngressDenyRule. It's publicly exported so the code generators
// can generate code for this structure.
//
// +deepequal-gen=true
type IngressCommonRule struct {
	// CacheSelector is the string representation of the selector used to select identities
	// +kubebuilder:validation:Optional
	CacheSelector string `json:"cacheSelector,omitempty"`

	// FromIdentities lists the source identities allowed by this rule
	// +kubebuilder:validation:Optional
	FromIdentities identity.NumericIdentitySlice `json:"fromIdentities,omitempty"`

	// FromCIDRs lists the source CIDRs allowed by this rule
	// +kubebuilder:validation:Optional
	FromCIDRs []string `json:"fromCIDRs,omitempty"`
}

// ResolvedIngressRule defines an ingress rule in the policy
type ResolvedIngressRule struct {
	IngressCommonRule `json:",inline"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp.
	//
	// +kubebuilder:validation:Optional
	ToPorts api.PortRules `json:"toPorts,omitempty"`

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is allowed to connect to.
	//
	// Example:
	// Any endpoint with the label "app=httpd" is allowed to initiate
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs api.ICMPRules `json:"icmps,omitempty"`
}

type ResolvedIngressDenyRule struct {
	IngressCommonRule `json:",inline"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp.
	//
	// +kubebuilder:validation:Optional
	ToPorts api.PortRules `json:"toPorts,omitempty"`

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is allowed to connect to.
	//
	// Example:
	// Any endpoint with the label "app=httpd" is allowed to initiate
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs api.ICMPRules `json:"icmps,omitempty"`
}

// EgressCommonRule is a rule that shares some of its fields across the
// ResolvedEgressRule and ResolvedEgressDenyRule. It's publicly exported so the code generators
// can generate code for this structure.
//
// +deepequal-gen:=true
type EgressCommonRule struct {
	// CacheSelector is the string representation of the selector used to select identities
	// +kubebuilder:validation:Optional
	CacheSelector string `json:"cacheSelector,omitempty"`

	// ToIdentities lists the destination identities allowed by this rule
	// +kubebuilder:validation:Optional
	ToIdentities identity.NumericIdentitySlice `json:"toIdentities,omitempty"`
}

// ResolvedEgressRule defines an egress rule in the policy
type ResolvedEgressRule struct {
	EgressCommonRule `json:",inline"`

	// ToFQDNs lists the destination FQDNs allowed by this rule
	// +kubebuilder:validation:Optional
	ToFQDNs []string `json:"toFQDNs,omitempty"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// connect to.
	//
	// Example:
	// Any endpoint with the label "role=frontend" is allowed to initiate
	// connections to destination port 8080/tcp
	//
	// +kubebuilder:validation:Optional
	ToPorts api.PortRules `json:"toPorts,omitempty"`

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is allowed to connect to.
	//
	// Example:
	// Any endpoint with the label "app=httpd" is allowed to initiate
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs api.ICMPRules `json:"icmps,omitempty"`
}

type ResolvedEgressDenyRules struct {
	EgressCommonRule `json:",inline"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// connect to.
	//
	// Example:
	// Any endpoint with the label "role=frontend" is allowed to initiate
	// connections to destination port 8080/tcp
	//
	// +kubebuilder:validation:Optional
	ToPorts api.PortRules `json:"toPorts,omitempty"`

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is allowed to connect to.
	//
	// Example:
	// Any endpoint with the label "app=httpd" is allowed to initiate
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs api.ICMPRules `json:"icmps,omitempty"`
}

// SyncState represents the synchronization state of the CRP
// +kubebuilder:validation:Enum=Pending;Synced;Error
// +kubebuilder:validation:Optional
type SyncState string

const (
	// SyncStatePending indicates that the policy is pending synchronization
	SyncStatePending SyncState = "Pending"
	// SyncStateSynced indicates that the policy is synchronized
	SyncStateSynced SyncState = "Synced"
	// SyncStateError indicates that there was an error during synchronization
	SyncStateError SyncState = "Error"
)

type PolicyType string

const (
	// PolicyTypeCNP represents CiliumNetworkPolicy
	// +kubebuilder:validation:Enum=CNP
	PolicyTypeCNP PolicyType = "CNP"
	// PolicyTypeCCNP represents CiliumClusterwideNetworkPolicy
	// +kubebuilder:validation:Enum=CCNP
	PolicyTypeCCNP PolicyType = "CCNP"
	// PolicyTypeKNP represents KubernetesNetworkPolicy
	// +kubebuilder:validation:Enum=KNP
	PolicyTypeKNP PolicyType = "KNP"
)

type CiliumResolvedPolicyID struct {
	SourcePolicyType      PolicyType `json:"sourcePolicyType"`
	SourcePolicyNamespace string     `json:"sourcePolicyNamespace,omitempty"`
	SourcePolicyName      string     `json:"sourcePolicyName"`
}
