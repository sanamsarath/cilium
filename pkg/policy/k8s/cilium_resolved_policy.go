package k8s

import (
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// getResourceTypeFromCRP determines the resource type from a CiliumResolvedPolicy.
func getResourceTypeFromCRP(crp *k8sTypes.SlimCRP) ipcacheTypes.ResourceKind {
	if crp.Spec != nil && crp.Spec.PolicyRef.Type != "" {
		// When using a policy reference, use the original policy's type
		switch crp.Spec.PolicyRef.Type {
		case "CNP":
			return ipcacheTypes.ResourceKindCNP
		case "CCNP":
			return ipcacheTypes.ResourceKindCCNP
		case "KNP":
			return ipcacheTypes.ResourceKindNetpol
		}
	}

	// Default or for direct CRP operations
	return ""
}

// onCRPUpsert handles CiliumResolvedPolicy update events.
func (p *policyWatcher) onCRPUpsert(crp *k8sTypes.SlimCRP, key resource.Key, apiGroup string, dc chan uint64) error {
	initialRecvTime := time.Now()

	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	oldCRP, ok := p.crpCache[key]
	if ok {
		// no generation change; this was a status update.
		if oldCRP.Generation == crp.Generation {
			return nil
		}
		if oldCRP.DeepEqual(crp) {
			return nil
		}

		p.log.Debug(
			"Modified CiliumResolvedPolicy",
			logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
			logfields.Name, crp.ObjectMeta.Name,
			logfields.K8sNamespace, crp.ObjectMeta.Namespace,
			logfields.AnnotationsOld, oldCRP.ObjectMeta.Annotations,
			logfields.Annotations, crp.ObjectMeta.Annotations,
		)
	}

	if dc != nil {
		p.crpSyncPending.Add(1)
	}

	// Create a resource ID for the CiliumResolvedPolicy
	// Use the original policy type for the resource ID if available
	resourceType := getResourceTypeFromCRP(crp)
	// if resourceType == "" {
	// 	p.log.Info("CiliumResolvedPolicy resource type is empty, not expected",
	// 		logfields.Name, crp.ObjectMeta.Name,)
	// 	return NewErrParse(fmt.Sprintf("Invalid Policy Resource Type in CiliumResolvedPolicy"))
	// }
	resourceID := ipcacheTypes.NewResourceID(
		resourceType,
		crp.Spec.PolicyRef.Namespace,
		crp.Spec.PolicyRef.Name,
	)

	// Sanitize the rules - this validates the rule spec
	if crp.Spec.Rule != nil {
		if err := crp.Spec.Rule.Sanitize(); err != nil {
			p.log.Info("CiliumResolvedPolicy rule sanitization failed",
				logfields.Name, crp.ObjectMeta.Name)
			return err
		}
	} else {
		p.log.Info("CiliumResolvedPolicy rule is nil, not expected",
			logfields.Name, crp.ObjectMeta.Name)
		return nil
	}

	// Import the resolved policy into the repository
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		ResolvedPolicy:      crp.CiliumResolvedPolicy,
		Source:              source.CustomResource,
		ProcessingStartTime: initialRecvTime,
		Resource:            resourceID,
		DoneChan:            dc,
	})

	// Update the cache
	p.crpCache[key] = crp

	p.log.Info("Imported CiliumResolvedPolicy",
		logfields.Name, crp.ObjectMeta.Name,
		logfields.K8sNamespace, crp.ObjectMeta.Namespace,
	)

	return nil
}

// onCRPDelete handles CiliumResolvedPolicy delete events.
func (p *policyWatcher) onCRPDelete(crp *k8sTypes.SlimCRP, key resource.Key, apiGroup string, dc chan uint64) {
	p.log.Debug("Deleting CiliumResolvedPolicy",
		logfields.Name, crp.ObjectMeta.Name,
		logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
		logfields.K8sNamespace, crp.ObjectMeta.Namespace,
	)

	// Create a resource ID for the CiliumResolvedPolicy
	resourceType := getResourceTypeFromCRP(crp)
	resourceID := ipcacheTypes.NewResourceID(
		resourceType,
		crp.ObjectMeta.Namespace,
		crp.ObjectMeta.Name,
	)

	if dc != nil {
		p.crpSyncPending.Add(1)
	}

	// Delete the policy from the repository
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Source:   source.CustomResource,
		Resource: resourceID,
		DoneChan: dc,
	})

	// Remove from cache
	delete(p.crpCache, key)

	p.log.Info("Deleted CiliumResolvedPolicy",
		logfields.Name, crp.ObjectMeta.Name,
		logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
		logfields.K8sNamespace, crp.ObjectMeta.Namespace,
	)

	p.k8sResourceSynced.SetEventTimestamp(apiGroup)
}
