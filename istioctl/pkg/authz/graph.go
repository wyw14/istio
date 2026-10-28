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
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/istioctl/pkg/cli"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/model/authzgraph"
)

const (
	graphOutputJSON = "json"

	useWaypointLabel = "istio.io/use-waypoint"
	// gatewayNameLabel mirrors label.IoK8sNetworkingGatewayGatewayName.
	gatewayNameLabel        = "gateway.networking.k8s.io/gateway-name"
	sidecarStatusAnnotation = "sidecar.istio.io/status"
	revLabelName            = "istio.io/rev"
	waypointClassName       = "istio-waypoint"
)

type graphOptions struct {
	files         []string
	useKube       bool
	output        string
	rootNamespace string
	revision      string
}

func graphCommand(ctx cli.Context) *cobra.Command {
	o := &graphOptions{useKube: true, output: graphOutputJSON}
	cmd := &cobra.Command{
		Use:   "graph [-f <file.yaml> ...]",
		Short: "Export the AuthorizationPolicy dependency graph as stable JSON",
		Long: `Prints the dependency graph of AuthorizationPolicy resources as stable JSON.

The graph connects policies to the workloads they select, the operations and sources
declared in their rules, and their targetRef bindings (Service, ServiceEntry, Gateway,
GatewayClass, HTTPRoute). Policies that apply to the same workload are linked with
override/combine relations following the CUSTOM -> DENY -> ALLOW -> AUDIT evaluation
order.

Cross-namespace targetRefs and fields unknown to the AuthorizationPolicy schema are
reported under distinct diagnostic codes. Exporting the graph performs no authorization
computation and never changes the configuration.

By default resources are read from the cluster. Use -f to read YAML/JSON manifests
(AuthorizationPolicy, Pod, Service, ServiceEntry, Gateway, GatewayClass, HTTPRoute,
Namespace) and --use-kube=false for fully offline operation.`,
		Example: `  # Export the graph for the whole mesh:
  istioctl experimental authz graph

  # Export from local manifests:
  istioctl experimental authz graph --use-kube=false -f policies.yaml -f workloads.yaml`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.output != graphOutputJSON {
				cmd.SilenceUsage = true
				return fmt.Errorf("unsupported output format %q (only %q is supported)", o.output, graphOutputJSON)
			}
			in, err := o.buildInput(cmd, ctx)
			if err != nil {
				return err
			}
			g := authzgraph.Build(in)
			out, err := json.MarshalIndent(g, "", "  ")
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(append(out, '\n'))
			return err
		},
	}
	cmd.Flags().StringSliceVarP(&o.files, "file", "f", nil,
		"YAML/JSON file (or directory) containing AuthorizationPolicy and related resources; repeatable")
	cmd.Flags().BoolVar(&o.useKube, "use-kube", true, "Use a Kubernetes cluster for source resources")
	cmd.Flags().StringVarP(&o.output, "output", "o", graphOutputJSON, "Output format (json)")
	cmd.Flags().StringVar(&o.rootNamespace, "root-namespace", "",
		"Override the mesh root namespace (mainly useful with --use-kube=false)")
	cmd.Flags().StringVar(&o.revision, "revision", "",
		"Restrict the graph to workloads of a specific control-plane revision")
	return cmd
}

// collected is the raw resource set gathered from files or a cluster.
type collected struct {
	policies        []authzgraph.PolicyInput
	workloads       []authzgraph.Workload
	services        []authzgraph.Service
	gateways        []authzgraph.Gateway
	gatewayClasses  []string
	httpRoutes      []types.NamespacedName
	namespaces      map[string]map[string]string // namespace -> merged labels/annotations
	serviceMetadata map[string]map[string]string // namespace/name -> merged labels/annotations
}

// assemble converts gathered resources into the graph input, including the
// waypoint-to-service enrollment used for Service/ServiceEntry targetRef binding.
func (o *graphOptions) assemble(c *collected) *authzgraph.Input {
	in := &authzgraph.Input{
		RootNamespace:  o.rootNamespace,
		Policies:       c.policies,
		Services:       c.services,
		Gateways:       c.gateways,
		GatewayClasses: c.gatewayClasses,
		HTTPRoutes:     c.httpRoutes,
	}

	gatewayClass := map[string]string{}
	for _, gw := range c.gateways {
		gatewayClass[gw.Namespace+"/"+gw.Name] = gw.GatewayClassName
	}

	for _, w := range c.workloads {
		gwName := w.Labels[gatewayNameLabel]
		w.IsWaypoint = gwName != "" && gatewayClass[w.Namespace+"/"+gwName] == waypointClassName
		if w.IsWaypoint {
			nsTarget := metadataValue(c.namespaces[w.Namespace], useWaypointLabel)
			for _, svc := range c.services {
				if svc.Namespace != w.Namespace {
					continue
				}
				// Namespace-wide enrollment attaches the waypoint to every service in
				// the namespace; otherwise the service must opt in by name.
				target := metadataValue(c.serviceMetadata[svc.Namespace+"/"+svc.Name], useWaypointLabel)
				if target == "" {
					target = nsTarget
				}
				if target == gwName {
					w.Services = append(w.Services, model.ServiceInfoForPolicyMatcher{
						Name:      svc.Name,
						Namespace: svc.Namespace,
						Registry:  svc.Registry,
					})
				}
			}
		}
		if o.revision == "" || w.Revision == o.revision {
			in.Workloads = append(in.Workloads, w)
		}
	}
	return in
}

// metadataValue returns a label/annotation value from a merged metadata map.
func metadataValue(meta map[string]string, key string) string {
	if meta == nil {
		return ""
	}
	return meta[key]
}

// mergeMetadata combines labels and annotations (labels win) for waypoint enrollment
// lookups, matching the GetUseWaypoint semantics of the ambient index.
func mergeMetadata(labels, annotations map[string]string) map[string]string {
	if len(labels) == 0 && len(annotations) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels)+len(annotations))
	for k, v := range annotations {
		out[k] = v
	}
	for k, v := range labels {
		out[k] = v
	}
	return out
}
