# Design Document: Centralized Policy Resolution for Cilium Agent

## Overview

This design document outlines the necessary changes to the Cilium agent to support centralized policy resolution. Currently, each Cilium agent (running as    // For CiliumResolvedPolicy
    crpSyncPending       atomic.Int32
    ciliumResolvedPolicies resource.Resource[*cilium_v2alpha1.CiliumResolvedPolicy]DaemonSet) i    i := &policyImporter{
        log:          cfg.Log,
        repo:         cfg.Repo,
        epm:          cfg.EndpointManager,
        ipc:          cfg.IPCache,
        monitorAgent: cfg.MonitorAgent,
        
        resolvedPolicyQ: make(chan *cilium_v2alpha1.CiliumResolvedPolicy, cfg.Config.PolicyQueueSize),
        q:               make(chan *policytypes.PolicyUpdate, cfg.Config.PolicyQueueSize),
        
        prefixesByResource: map[ipcachetypes.ResourceID][]netip.Prefix{},
    }ndently watches policy events, computes the mapping between rules and affected identities, and applies these policies. This redundant computation across all agents causes significant resource overhead and increased load on the Kubernetes API server, especially in large clusters.

The centralized policy resolution approach aims to:
1. Reduce redundant policy computation
2. Decrease load on the Kubernetes API server
3. Improve scalability in large clusters
4. Minimize resource utilization

## Current Architecture

In the existing architecture, each Cilium agent:
1. Watches for policy events via the PolicyWatcher
2. Processes these events through the PolicyImporter
3. Updates the PolicyRepository with new rules
4. Maps rules to identities using SelectorCache
5. Regenerates endpoints as needed

The key bottleneck is that the mapping of rules to identities happens independently in every agent, causing redundant computation.

## Proposed Changes

### New CRD: CiliumResolvedPolicy

We will introduce a new CRD called `CiliumResolvedPolicy` that will contain pre-computed mappings between rules and identities. This resource is cluster-scoped and contains:

1. A reference to the original policy (CNP, CCNP, or KNP)
2. The original rule from the source policy
3. Pre-computed mappings between endpoint selectors and the numeric identities they match
4. Separate mappings for ingress and egress rule selectors

The structure of the CiliumResolvedPolicy allows agents to efficiently apply policies without having to compute identity-selector mappings themselves:

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumResolvedPolicy
metadata:
  name: resolved-policy-{hash}
spec:
  policyRef:
    name: example-policy
    namespace: default
    type: CNP
    uid: "abcd1234-5678-90ab-cdef-1234567890ab"
    resourceVersion: "12345"
  ruleSelector:
    selector:
      matchLabels:
        app: myapp
    identities: [1234, 5678]
  ingressRuleSelectors:
    - selector:
        matchLabels:
          role: frontend
      identities: [1234, 5678]
  egressRuleSelectors:
    - selector:
        matchLabels:
          role: database
      identities: [9012]
  rule:
    endpointSelector:
      matchLabels:
        app: myapp
    ingress:
      - fromEndpoints:
          - matchLabels:
              role: frontend
    egress:
      - toEndpoints:
          - matchLabels:
              role: database
status:
  processed: true
  processingTime: "2025-04-27T12:00:00Z"
```

### Changes to PolicyWatcher in pkg/policy/k8s/cell.go

The existing policy watcher in `startK8sPolicyWatcher` function needs to be extended to support watching for CiliumResolvedPolicy resources when centralized mode is enabled:

```go
func startK8sPolicyWatcher(params PolicyWatcherParams) {
    if !params.ClientSet.IsEnabled() {
        return // skip watcher if K8s is not enabled
    }

    // We want to subscribe before the start hook is invoked in order to not miss
    // any events
    ctx, cancel := context.WithCancel(context.Background())

    p := &policyWatcher{
        log:                              params.Logger,
        config:                           params.Config,
        policyImporter:                   params.PolicyImporter,
        k8sResourceSynced:                params.K8sResourceSynced,
        k8sAPIGroups:                     params.K8sAPIGroups,
        svcCache:                         params.ServiceCache,
        ipCache:                          params.IPCache,
        ciliumNetworkPolicies:            params.CiliumNetworkPolicies,
        ciliumClusterwideNetworkPolicies: params.CiliumClusterwideNetworkPolicies,
        ciliumCIDRGroups:                 params.CiliumCIDRGroups,
        ciliumResolvedPolicies:           params.CiliumResolvedPolicies, // New field for resolved policies
        networkPolicies:                  params.NetworkPolicies,

        cnpCache:       make(map[resource.Key]*types.SlimCNP),
        cidrGroupCache: make(map[string]*cilium_v2_alpha1.CiliumCIDRGroup),
        cidrGroupCIDRs: make(map[string]sets.Set[netip.Prefix]),

        toServicesPolicies: make(map[resource.Key]struct{}),
        cnpByServiceID:     make(map[k8s.ServiceID]map[resource.Key]struct{}),
        metricsManager:     params.MetricsManager,
    }

    // Service notifications are not used if CNPs/CCNPs are disabled.
    if params.Config.EnableCiliumNetworkPolicy || params.Config.EnableCiliumClusterwideNetworkPolicy {
        p.svcCacheNotifications = serviceNotificationsQueue(ctx, params.ServiceCache.Notifications())
    }

    params.Lifecycle.Append(cell.Hook{
        OnStart: func(startCtx cell.HookContext) error {
            p.watchResources(ctx)
            return nil
        },
        OnStop: func(cell.HookContext) error {
            if cancel != nil {
                cancel()
            }
            return nil
        },
    })

    // Register watchers based on the centralized policy resolution mode
    if params.Config.EnableCentralizedNetworkPolicy {
        // When centralized mode is enabled, we ONLY watch for resolved policies
        // and disable ALL other policy watchers to reduce load on the API server
        p.crpSyncPending.Store(1)
        p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumResolvedPolicyV2Alpha1, func() bool {
            return p.crpSyncPending.Load() == 0
        })
        
        // CIDR Groups are not needed in centralized mode because the resolved policies 
        // already contain the pre-computed CIDR information
    } else {
        // In distributed mode, register all standard policy watchers
        if params.Config.EnableK8sNetworkPolicy {
            p.knpSyncPending.Store(1)
            p.registerResourceWithSyncFn(ctx, k8sAPIGroupNetworkingV1Core, func() bool {
                return p.knpSyncPending.Load() == 0
            })
        }
        
        if params.Config.EnableCiliumNetworkPolicy {
            p.cnpSyncPending.Store(1)
            p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumNetworkPolicyV2, func() bool {
                return p.cnpSyncPending.Load() == 0 && p.cidrGroupSynced.Load()
            })
        }

        if params.Config.EnableCiliumClusterwideNetworkPolicy {
            p.ccnpSyncPending.Store(1)
            p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, func() bool {
                return p.ccnpSyncPending.Load() == 0 && p.cidrGroupSynced.Load()
            })
        }
        
        // CIDR Groups are only needed in distributed mode
        if params.Config.EnableCiliumNetworkPolicy || params.Config.EnableCiliumClusterwideNetworkPolicy {
            p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumCIDRGroupV2Alpha1, func() bool {
                return p.cidrGroupSynced.Load()
            })
        }
    }
}
```

Also, we need to define a new constant for the CiliumResolvedPolicy API Group:

```go
const (
    k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
    k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
    k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
    k8sAPIGroupCiliumCIDRGroupV2Alpha1          = "cilium/v2alpha1::CiliumCIDRGroup"
    k8sAPIGroupCiliumResolvedPolicyV2Alpha1     = "cilium/v2alpha1::CiliumResolvedPolicy" // New API group
)
```

### Changes to PolicyWatcherParams struct

We need to update the `PolicyWatcherParams` struct to include the CiliumResolvedPolicies resource:

```go
type PolicyWatcherParams struct {
    cell.In

    Lifecycle cell.Lifecycle

    ClientSet client.Clientset
    Config    *option.DaemonConfig
    Logger    *slog.Logger

    K8sResourceSynced *synced.Resources
    K8sAPIGroups      *synced.APIGroups

    ServiceCache   k8s.ServiceCache
    IPCache        *ipcache.IPCache
    PolicyImporter policycell.PolicyImporter

    CiliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
    CiliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
    CiliumCIDRGroups                 resource.Resource[*cilium_v2_alpha1.CiliumCIDRGroup]
    CiliumResolvedPolicies           resource.Resource[*cilium_v2_alpha1.CiliumResolvedPolicy] // New resource
    NetworkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]

    MetricsManager CNPMetrics
}
```

### PolicyWatcher Structure Update

The `policyWatcher` struct also needs to be updated to include fields for tracking resolved policies:

```go
type policyWatcher struct {
    // ...existing code...
    
    // For CiliumResolvedPolicy
    resolvedPolicySyncPending atomic.Int32
    ciliumResolvedPolicies    resource.Resource[*cilium_v2_alpha1.CiliumResolvedPolicy]
    
    // ...existing code...
}
```

### Changes to PolicyImporter

The PolicyImporter interface needs to be extended to support resolved policies:

```go
// In pkg/policy/cell/policy_importer.go
type PolicyImporter interface {
    UpdatePolicy(*policytypes.PolicyUpdate)
    UpdateResolvedPolicy(*cilium_v2alpha1.CiliumResolvedPolicy) error
}

type policyImporter struct {
    // ...existing code...
    resolvedPolicyQ chan *cilium_v2alpha1.CiliumResolvedPolicy  // New channel for resolved policies
    // ...existing code...
}

func newPolicyImporter(cfg policyImporterParams) PolicyImporter {
    i := &policyImporter{
        // ...existing code...
        resolvedPolicyQ: make(chan *cilium_v2alpha1.CiliumResolvedPolicy, cfg.Config.PolicyQueueSize),
        // ...existing code...
    }

    // Existing code for regular policy updates
    buf := stream.Buffer(
        stream.FromChannel(i.q),
        int(cfg.Config.PolicyQueueSize), 10*time.Millisecond,
        concat)

    cfg.JobGroup.Add(job.Observer("policy-importer", i.processUpdates, buf))
    
    // New buffer and job for resolved policy updates
    resolvedBuf := stream.Buffer(
        stream.FromChannel(i.resolvedPolicyQ),
        int(cfg.Config.PolicyQueueSize), 10*time.Millisecond,
        concatResolved)

    cfg.JobGroup.Add(job.Observer("resolved-policy-importer", i.processResolvedPolicyUpdates, resolvedBuf))

    return i
}

func concatResolved(buf []*cilium_v2alpha1.CiliumResolvedPolicy, in *cilium_v2alpha1.CiliumResolvedPolicy) []*cilium_v2alpha1.CiliumResolvedPolicy {
    buf = append(buf, in)
    return buf
}

func (i *policyImporter) UpdateResolvedPolicy(resolvedPolicy *cilium_v2alpha1.CiliumResolvedPolicy) error {
    // Queue the resolved policy update for processing
    i.resolvedPolicyQ <- resolvedPolicy
    return nil
}

// processResolvedPolicyUpdates is similar to processUpdates but handles resolved policies
// with pre-computed identity mappings
func (i *policyImporter) processResolvedPolicyUpdates(ctx context.Context, updates []*cilium_v2alpha1.CiliumResolvedPolicy) error {
    if len(updates) == 0 {
        return nil
    }

    i.log.Info("Processing resolved policy updates", logfields.Count, len(updates))
    
    // We don't need to handle CIDR prefixes here separately, 
    // expecting them to be pre-computed and published by
    // centralized policy controller.

    
    // Process each resolved policy to update the repository
    idsToRegen := &set.Set[identity.NumericIdentity]{}
    startRevision := i.repo.GetRevision()
    endRevision := startRevision
    
    for _, resolvedPolicy := range updates {
        // For resolved policies, we use ImportResolvedPolicy on the repository
        // which will handle the pre-computed identity mappings from the CiliumResolvedPolicy
        // and return the affected identities that need regeneration
        affectedIdentities, newRevision, err := i.repo.ImportResolvedPolicy(resolvedPolicy)
        if err != nil {
            i.log.Error("Failed to import resolved policy",
                logfields.Error, err,
                logfields.Resource, resolvedPolicy.Name)
            continue
        }
        
        endRevision = newRevision
        idsToRegen.Merge(*affectedIdentities)
        
                
        // Send monitor notification similar to regular policy updates
        // ....same as in processUpdates...
    }
    
    // Regenerate affected endpoints
    i.log.Info("Resolved policy repository updates complete, triggering endpoint updates",
        logfields.PolicyRevision, endRevision)
    if i.epm != nil {
        i.epm.UpdatePolicy(idsToRegen, startRevision, endRevision)
    }
    
    // Record metrics for policy application
    // ....same as in processUpdates...    
    
    // Clean up stale prefixes, if CIDRS are handled separately
    
    return nil
}
```

### Changes to PolicyRepository

The PolicyRepository interface needs a new method to directly import resolved policies:

```go
// In pkg/policy/repository.go
type Repository Struct {
    // ...existing code...
    ImportResolvedPolicy(resolvedPolicy *cilium_v2alpha1.CiliumResolvedPolicy) (*set.Set[identity.NumericIdentity], uint64, error)
    // ...existing code...
}

// This is similar to ReplaceByResourceID function in the existing repository used for updating normal policies.
func (p *policyRepository) ImportResolvedPolicy(resolvedPolicy *cilium_v2alpha1.CiliumResolvedPolicy) (*set.Set[identity.NumericIdentity], uint64, error) {
    // TODO: Implement this method with the following steps:
    
    // 1. Lock the repository mutex
    
    // 2. Create a set to collect affected identities
    
    // 3. Construct a resourceID from the PolicyRef information
    
    // 4. If this is a delete operation (resolvedPolicy is nil or has no rule):
    //    a. Find and remove rules associated with this resource
    //    b. Collect affected identities from the removed rules
    //    c. Update repository revision number
    //    d. Return affected identities and revision
    
    // 5. For add/update operations:
    //    a. Create a Rule instance based on resolvedPolicy.Spec.Rule
    //    b. Use the pre-computed identities from resolvedPolicy instead of calculating them:
    //       - For endpoint selector (resolvedPolicy.Spec.RuleSelector)
    //       - For ingress rules (resolvedPolicy.Spec.IngressRuleSelectors)
    //       - For egress rules (resolvedPolicy.Spec.EgressRuleSelectors)
    //    c. Insert the rule into the repository
    //    d. Collect all affected identities
    //    e. Update repository revision number
    //    f. Return affected identities and revision
    
    // Placeholder implementation
    return &set.Set[identity.NumericIdentity]{}, p.revision, nil
}
```

Helper function to convert policy type to resource kind:

```go
// TODO: Helper functions needed for implementation:

// 1. A function to convert policy type to resource kind:
//    - Convert CNP to ResourceKindCiliumNetworkPolicy
//    - Convert CCNP to ResourceKindCiliumClusterwideNetworkPolicy
//    - Convert KNP to ResourceKindNetworkPolicy

// 2. Function(s) to apply pre-computed identities:
//    - Apply pre-computed identities to endpoint selectors
//    - Apply pre-computed identities to ingress rule selectors
//    - Apply pre-computed identities to egress rule selectors
//    - Handle special cases like CIDRs, entities, etc.
```

## Endpoint Regeneration Flow

### When Policy Changes

1. The PolicyWatcher detects a change to a CiliumResolvedPolicy resource
2. The PolicyImporter processes this change via `UpdateResolvedPolicy`
3. The PolicyImporter buffers events and processes them in batches via `processResolvedPolicyUpdates`
4. Each resolved policy is imported into the PolicyRepository via `ImportResolvedPolicy`
5. Affected identities are collected and merged across all policy updates
6. Metrics are recorded for policy implementation delay
7. The EndpointManager is notified to regenerate affected endpoints

```
┌────────────────┐      ┌────────────────┐      ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│                │      │                │      │                │      │                │      │                │
│  PolicyWatcher │─────▶│ PolicyImporter │─────▶│processResolved│─────▶│    Policy     │─────▶│   Endpoint    │
│  (watches CRP) │      │(UpdateResolved)│      │PolicyUpdates  │      │  Repository   │      │ Regeneration  │
│                │      │                │      │               │      │   (Import)    │      │               │
└────────────────┘      └────────────────┘      └────────────────┘      └────────────────┘      └────────────────┘
                                                       
```

### When New Endpoint is Created

1. New endpoint is created with a set of identities
2. The endpoint constructor calls `RegeneratePolicy` on the endpoint
3. The endpoint's `regeneratePolicy` method retrieves applicable policies from the PolicyRepository
4. The PolicyRepository returns pre-computed policy decisions based on the endpoint's identities
5. The endpoint is configured with the appropriate policies without recomputing identity mappings

```
┌────────────────┐      ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│                │      │                │      │                │      │                │
│    Endpoint    │─────▶│ RegeneratePolicy ────▶│  Policy Repo  │─────▶│   Configure   │
│    Creation    │      │                │      │   (Lookup)    │      │    Endpoint   │
│                │      │                │      │               │      │               │
└────────────────┘      └────────────────┘      └────────────────┘      └────────────────┘
                                                       │                       │
                                                       │                       │
                                                       ▼                       ▼
                                               ┌────────────────┐      ┌────────────────┐
                                               │                │      │                │
                                               │  Pre-computed  │      │   Update BPF   │
                                               │Policy Decisions│      │ Policy Maps    │
                                               │                │      │                │
                                               └────────────────┘      └────────────────┘
```

## Performance Considerations

1. Reduced CPU and memory usage across the cluster as identity resolution happens only once
2. Reduced API server load due to fewer policy watches (only one component watches raw policies)

## Implementation steps

1. Implement core changes to PolicyWatcher
   - Add support for CiliumResolvedPolicy resource watching
   - Modify configuration to conditionally watch policies based on EnableCentralizedNetworkPolicy flag

2. Extend PolicyImporter with resolved policy support
   - Implement UpdateResolvedPolicy method
   - Add queue and processing function for resolved policies
   - Handle pre-computed identity mappings from the selectors

3. Update PolicyRepository
   - Add ImportResolvedPolicy method to directly apply pre-computed policy rules with their identity mappings
   - Create utility functions to override identity mappings in the selector cache
   - Ensure proper rule insertion and deletion with pre-computed identity information

4. Update Endpoint Regeneration Flow
   - Ensure endpoint regeneration works properly with pre-computed policy mappings
   - Test regeneration efficiency compared to distributed policy computation

5. Implement Metrics and Observability
   - Track policy implementation time and success rate
   - Add metrics for comparing centralized vs. distributed policy performance
   - Add debugging capabilities for troubleshooting policy issues

6. Documentation and Testing
   - Update documentation and user guides
   - Add integration tests to verify both modes work correctly
   - Implement migration testing for switching between modes

7. Optimize Policy Repository
   - Refine data structures for more efficient storage of pre-computed policies
   - Optimize lookup paths for improved performance in centralized mode

## Note on Centralized Identity Allocation

Beta version changes for centralized identity allocation are already supported. This functionality complements the centralized policy resolution approach and the code interactions will need to be understood in a subsequent phase.

## Conclusion

The centralized policy computation architecture offers significant advantages for large Kubernetes clusters running Cilium:

1. **Reduced Redundancy**: Policy computation happens once instead of being repeated on every agent
2. **Lower API Server Load**: Fewer policy watches reduce API server resource usage
3. **Improved Scalability**: Agents in large clusters operate more efficiently with pre-computed policies
4. **Reduced Resource Usage**: Agents require less CPU and memory when not computing policies themselves
5. **Consistent Policy Application**: Centralized computation ensures all agents get identical policy results

These benefits make the centralized policy approach especially valuable for large-scale deployments where policy computation represents a significant portion of agent overhead.