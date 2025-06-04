# Design Document: Centralized Policy Resolution for Cilium Agent

## Overview

This design document outlines the necessary changes to the Cilium agent to support centralized policy resolution. Currently, each Cilium agent (running as a DaemonSet) independently watches policy events, computes the mapping between rules and affected identities, and applies these policies. This redundant computation across all agents causes significant resource overhead and increased load on the Kubernetes API server, especially in large clusters.

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

1. Implement core changes to PolicyWatcher, PolicyImporter, and PolicyRepository
2. Implement support for handling resolved policies in endpoint regeneration
3. Implement metrics and observability for the new policy resolution path
4. Implement seamless switching between centralized and distributed policy resolution
5. Test and validate the new architecture in a staging environment
6. Optimize policy repository with data structures more light weight and efficient for the centralized mode.

## Note on Centralized Identity Allocation

Beta version changes for centralized identity allocation are already supported. This functionality complements the centralized policy resolution approach and the code interactions will need to be understood in a subsequent phase.