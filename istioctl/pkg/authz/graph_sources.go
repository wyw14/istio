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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"

	"istio.io/istio/istioctl/pkg/cli"
	crdconv "istio.io/istio/pilot/pkg/config/kube/crd"
	"istio.io/istio/pilot/pkg/model/authzgraph"
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/schema/collections"
	sigsyaml "sigs.k8s.io/yaml"
)

func (o *graphOptions) buildInput(cmd *cobra.Command, ctx cli.Context) (*authzgraph.Input, error) {
	if len(o.files) > 0 || !o.useKube {
		if len(o.files) == 0 {
			return nil, fmt.Errorf("no input files: pass -f <file> or enable --use-kube")
		}
		c, err := collectFromFiles(o.files)
		if err != nil {
			return nil, err
		}
		if o.rootNamespace == "" {
			o.rootNamespace = mesh.DefaultMeshConfig().GetRootNamespace()
		}
		cmd.SilenceUsage = true
		return o.assemble(c), nil
	}

	c, err := collectFromCluster(ctx)
	if err != nil {
		return nil, err
	}
	if o.rootNamespace == "" {
		o.rootNamespace = c.rootNamespace
	}
	cmd.SilenceUsage = true
	return o.assemble(&c.collected), nil
}

// clusterResult adds the mesh root namespace discovered from the mesh config map.
type clusterResult struct {
	collected
	rootNamespace string
}

func collectFromCluster(ctx cli.Context) (*clusterResult, error) {
	client, err := ctx.CLIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	c := &clusterResult{
		collected: collected{
			namespaces:      map[string]map[string]string{},
			serviceMetadata: map[string]map[string]string{},
		},
		rootNamespace: mesh.DefaultMeshConfig().GetRootNamespace(),
	}
	ns := ctx.Namespace()
	cctx := context.TODO()

	// Root namespace from the mesh config map (revision-aware, like other commands).
	if mc := readMeshRootNamespace(client, ctx); mc != "" {
		c.rootNamespace = mc
	}

	authzList, err := client.Dynamic().Resource(authorizationPoliciesGVR()).
		Namespace(ns).List(cctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list AuthorizationPolicy: %w", err)
	}
	for i := range authzList.Items {
		if err := addAuthorizationPolicy(&c.collected, &authzList.Items[i]); err != nil {
			return nil, err
		}
	}

	pods, err := client.Kube().CoreV1().Pods(ns).List(cctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}
	for i := range pods.Items {
		if wl, ok := workloadFromPod(&pods.Items[i]); ok {
			c.workloads = append(c.workloads, wl)
		}
	}

	services, err := client.Kube().CoreV1().Services(ns).List(cctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}
	for i := range services.Items {
		s := &services.Items[i]
		c.services = append(c.services, authzgraph.Service{
			Name: s.Name, Namespace: s.Namespace, Registry: provider.Kubernetes,
		})
		c.serviceMetadata[s.Namespace+"/"+s.Name] = mergeMetadata(s.Labels, s.Annotations)
	}

	// Namespace labels/annotations drive namespace-wide waypoint enrollment.
	if ns == "" || ns == metav1.NamespaceAll {
		nss, err := client.Kube().CoreV1().Namespaces().List(cctx, metav1.ListOptions{})
		if err == nil {
			for i := range nss.Items {
				n := &nss.Items[i]
				c.namespaces[n.Name] = mergeMetadata(n.Labels, n.Annotations)
			}
		}
	} else {
		n, err := client.Kube().CoreV1().Namespaces().Get(cctx, ns, metav1.GetOptions{})
		if err == nil {
			c.namespaces[n.Name] = mergeMetadata(n.Labels, n.Annotations)
		}
	}

	if err := collectClusterDynamic(cctx, client, &c.collected, ns); err != nil {
		return nil, err
	}
	return c, nil
}

func collectFromFiles(paths []string) (*collected, error) {
	c := &collected{
		namespaces:      map[string]map[string]string{},
		serviceMetadata: map[string]map[string]string{},
	}
	files, err := expandFiles(paths)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", file, err)
		}
		if err := decodeDocs(data, c); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}
	}
	return c, nil
}

func expandFiles(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := filepath.Ext(path)
			if ext == ".yaml" || ext == ".yml" || ext == ".json" {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func decodeDocs(data []byte, c *collected) error {
	reader := kubeyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		doc, err := reader.Read()
		if err != nil {
			break
		}
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}
		var u unstructured.Unstructured
		if err := sigsyaml.Unmarshal(doc, &u); err != nil {
			return err
		}
		if len(u.Object) == 0 {
			continue
		}
		if err := addUnstructured(c, &u); err != nil {
			return err
		}
	}
	return nil
}

func addUnstructured(c *collected, u *unstructured.Unstructured) error {
	g := u.GroupVersionKind()
	switch {
	case g.Group == "security.istio.io" && g.Kind == "AuthorizationPolicy":
		return addAuthorizationPolicy(c, u)
	case g.Group == "" && g.Kind == "Pod":
		var pod corev1.Pod
		if err := sigsyaml.Unmarshal(canonicalJSON(u), &pod); err != nil {
			return err
		}
		if wl, ok := workloadFromPod(&pod); ok {
			c.workloads = append(c.workloads, wl)
		}
	case g.Group == "" && g.Kind == "Service":
		var svc corev1.Service
		if err := sigsyaml.Unmarshal(canonicalJSON(u), &svc); err != nil {
			return err
		}
		c.services = append(c.services, authzgraph.Service{
			Name: svc.Name, Namespace: svc.Namespace, Registry: provider.Kubernetes,
		})
		c.serviceMetadata[svc.Namespace+"/"+svc.Name] = mergeMetadata(svc.Labels, svc.Annotations)
	case g.Group == "" && g.Kind == "Namespace":
		var ns corev1.Namespace
		if err := sigsyaml.Unmarshal(canonicalJSON(u), &ns); err != nil {
			return err
		}
		c.namespaces[ns.Name] = mergeMetadata(ns.Labels, ns.Annotations)
	case g.Group == "networking.istio.io" && g.Kind == "ServiceEntry":
		name, _ := nestedString(u, "metadata", "name")
		namespace, _ := nestedString(u, "metadata", "namespace")
		if namespace == "" {
			namespace = metav1.NamespaceDefault
		}
		c.services = append(c.services, authzgraph.Service{
			Name: name, Namespace: namespace, Registry: provider.External,
		})
		c.serviceMetadata[namespace+"/"+name] = mergeMetadata(
			nestedMap(u, "metadata", "labels"), nestedMap(u, "metadata", "annotations"))
	case g.Group == "gateway.networking.k8s.io" && g.Kind == "Gateway":
		name, _ := nestedString(u, "metadata", "name")
		namespace, _ := nestedString(u, "metadata", "namespace")
		className, _ := nestedString(u, "spec", "gatewayClassName")
		c.gateways = append(c.gateways, authzgraph.Gateway{
			Name: name, Namespace: namespace, GatewayClassName: className,
			Revision: nestedMap(u, "metadata", "labels")[revLabelName],
		})
	case g.Group == "gateway.networking.k8s.io" && g.Kind == "GatewayClass":
		name, _ := nestedString(u, "metadata", "name")
		c.gatewayClasses = append(c.gatewayClasses, name)
	case g.Group == "gateway.networking.k8s.io" && g.Kind == "HTTPRoute":
		name, _ := nestedString(u, "metadata", "name")
		namespace, _ := nestedString(u, "metadata", "namespace")
		c.httpRoutes = append(c.httpRoutes, namespacedName(namespace, name))
	}
	return nil
}

func nestedMap(u *unstructured.Unstructured, fields ...string) map[string]string {
	raw, _, err := unstructured.NestedStringMap(u.Object, fields...)
	if err != nil || raw == nil {
		return nil
	}
	return raw
}

func nestedString(u *unstructured.Unstructured, fields ...string) (string, bool) {
	v, found, err := unstructured.NestedString(u.Object, fields...)
	if err != nil || !found {
		return "", false
	}
	return v, true
}

// canonicalJSON re-marshals the unstructured object so typed Kubernetes objects can be
// decoded without carrying over YAML-specific scalar handling.
func canonicalJSON(u *unstructured.Unstructured) []byte {
	b, err := json.Marshal(u.Object)
	if err != nil {
		return nil
	}
	return b
}

func addAuthorizationPolicy(c *collected, u *unstructured.Unstructured) error {
	schema, ok := collections.All.FindByGroupVersionAliasesKind(config.GroupVersionKind{
		Group:   u.GroupVersionKind().Group,
		Version: u.GroupVersionKind().Version,
		Kind:    u.GroupVersionKind().Kind,
	})
	if !ok {
		return fmt.Errorf("no schema for %s", u.GroupVersionKind().String())
	}
	js, err := json.Marshal(u.Object)
	if err != nil {
		return err
	}
	var ik crdconv.IstioKind
	if err := json.Unmarshal(js, &ik); err != nil {
		return err
	}
	cfg, err := crdconv.ConvertObject(schema, &ik, "")
	if err != nil {
		return err
	}
	c.policies = append(c.policies, authzgraph.PolicyInput{Config: *cfg, Raw: u.Object})
	return nil
}

func workloadFromPod(pod *corev1.Pod) (authzgraph.Workload, bool) {
	_, isGateway := pod.Labels[gatewayNameLabel]
	_, hasSidecar := pod.Annotations[sidecarStatusAnnotation]
	_, hasRevision := pod.Labels[revLabelName]
	if !isGateway && !hasSidecar && !hasRevision {
		return authzgraph.Workload{}, false
	}
	return authzgraph.Workload{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Labels:    labels.Instance(pod.Labels),
		Revision:  pod.Labels[revLabelName],
	}, true
}
