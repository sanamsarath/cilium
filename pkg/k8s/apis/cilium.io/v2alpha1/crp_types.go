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

//+genclient
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:resource:categories={cilium},singular="ciliumresolvedpolicy",path="ciliumresolvedpolicies",scope="Cluster",shortName={crp}
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CiliumResolvedPolicy is the resolved policy object for CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, and KubernetesNetworkPolicy
type CiliumResolvedPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of CiliumResolvedPolicy
	Spec CiliumResolvedPolicySpec `json:"spec"`

	// Specs defines the list of resolved policy specs
	Specs []CiliumResolvedPolicySpec `json:"specs,omitempty"`

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
	// PolicyRef defines the source policy information
	// +kubebuilder:validation:Required
	PolicyRef PolicyRef `json:"policy"`

	// AppliesTo defines endpoints to which this policy applies
	// +kubebuilder:validation:Required
	AppliesTo AppliesTo `json:"appliesTo"`

	// IngressRules defines the ingress rules for this policy
	// +kubebuilder:validation:Optional
	IngressRules []IngressResolvedRule `json:"ingressRules,omitempty"`

	// IngressDenyRules defines the ingress deny rules for this policy
	// +kubebuilder:validation:Optional
	IngressDenyRules []IngressResolvedRule `json:"ingressDenyRules,omitempty"`

	// EgressRules defines the egress rules for this policy
	// +kubebuilder:validation:Optional
	EgressRules []EgressResolvedRule `json:"egressRules,omitempty"`

	// EgressDenyRules defines the egress deny rules for this policy
	// +kubebuilder:validation:Optional
	EgressDenyRules []EgressResolvedRule `json:"egressDenyRules,omitempty"`
}

// CiliumResolvedPolicyStatus defines the observed state of CiliumResolvedPolicy
type CiliumResolvedPolicyStatus struct {
	// LastUpdated represents the time when this policy was last updated
	LastUpdated slimv1.Time `json:"lastUpdated,omitempty"`
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
	// +kubebuilder:validation:Required
	Identities identity.NumericIdentitySlice `json:"identities"`

	// PodSelectorLabels is the list of labels that select the pods to which this policy applies
	// +kubebuilder:validation:Optional
	PodSelectorLabels []PodSelectorLabel `json:"podSelectorLabels,omitempty"`
}

// PodSelectorLabel represents a key-value label pair
type PodSelectorLabel struct {
	// Key is the label key
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// Value is the label value
	// +kubebuilder:validation:Optional
	Value string `json:"value,omitempty"`
}

// IngressRule defines an ingress rule in the policy
type IngressResolvedRule struct {
	// RuleIndex is the index of this rule in the original policy
	// +kubebuilder:validation:Required
	RuleIndex int `json:"ruleIndex"`

	// FromIdentities lists the source identities allowed by this rule
	// +kubebuilder:validation:Optional
	FromIdentities identity.NumericIdentitySlice `json:"fromIdentities,omitempty"`

	// FromCIDRs lists the source CIDRs allowed by this rule
	// +kubebuilder:validation:Optional
	FromCIDRs []string `json:"fromCIDRs,omitempty"`

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
	// which the endpoint subject to the rule is allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs api.ICMPRules `json:"icmps,omitempty"`
}

// EgressRule defines an egress rule in the policy
type EgressResolvedRule struct {
	// RuleIndex is the index of this rule in the original policy
	// +kubebuilder:validation:Required
	RuleIndex int `json:"ruleIndex"`

	// ToIdentities lists the destination identities allowed by this rule
	// +kubebuilder:validation:Optional
	ToIdentities identity.NumericIdentitySlice `json:"toIdentities,omitempty"`

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
	// which the endpoint subject to the rule is allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
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
