// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authz

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/istioctl/pkg/cli"
	istioctlutil "istio.io/istio/istioctl/pkg/util"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube"
)

func namespacedName(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}

func authorizationPoliciesGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group: "security.istio.io", Version: "v1beta1", Resource: "authorizationpolicies",
	}
}

func collectClusterDynamic(ctx context.Context, client kube.CLIClient, c *collected, namespace string) error {
	namespaced := []schema.GroupVersionResource{
		{Group: "networking.istio.io", Version: "v1beta1", Resource: "serviceentries"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"},
	}
	for _, gvr := range namespaced {
		list, err := client.Dynamic().Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			// CRD may not be installed; skip optional resources but hard-fail other errors.
			if isNotFound(err) {
				continue
			}
			return fmt.Errorf("failed to list %s: %w", gvr.Resource, err)
		}
		for i := range list.Items {
			if err := addUnstructured(c, &list.Items[i]); err != nil {
				return err
			}
		}
	}

	classList, err := client.Dynamic().Resource(schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses",
	}).List(ctx, metav1.ListOptions{})
	if err != nil {
		if !isNotFound(err) {
			return fmt.Errorf("failed to list gatewayclasses: %w", err)
		}
	} else {
		for i := range classList.Items {
			item := classList.Items[i]
			if err := addUnstructured(c, &item); err != nil {
				return err
			}
		}
	}
	return nil
}

func isNotFound(err error) bool {
	return apierrors.IsNotFound(err)
}

// readMeshRootNamespace reads rootNamespace from the mesh config map; empty string is
// returned when the config map is unavailable so callers fall back to defaults.
func readMeshRootNamespace(client kube.CLIClient, ctx cli.Context) string {
	name := istioctlutil.DefaultMeshConfigMapName
	if rev := client.Revision(); rev != "" && rev != "default" {
		name = fmt.Sprintf("%s-%s", istioctlutil.DefaultMeshConfigMapName, rev)
	}
	cm, err := client.Kube().CoreV1().ConfigMaps(ctx.IstioNamespace()).
		Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	yamlText, ok := cm.Data[istioctlutil.ConfigMapKey]
	if !ok {
		return ""
	}
	mc, err := mesh.ApplyMeshConfigDefaults(yamlText)
	if err != nil {
		return ""
	}
	return mc.GetRootNamespace()
}
