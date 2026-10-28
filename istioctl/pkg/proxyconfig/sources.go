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

package proxyconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"istio.io/istio/istioctl/pkg/cli"
	"istio.io/istio/istioctl/pkg/completion"
	"istio.io/istio/pkg/kube"
)

// resourceSource mirrors pilot/pkg/model.ResourceSource over the debug API.
type resourceSource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Version   string `json:"version,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
}

// resourceSourceEntry is one resource and its origins in the debug API.
type resourceSourceEntry struct {
	Type    string           `json:"type"`
	Name    string           `json:"name"`
	Sources []resourceSource `json:"sources"`
}

// resourceSourcesDebug is the /debug/resource_sources payload for one proxy.
type resourceSourcesDebug struct {
	ProxyID   string                `json:"proxyID"`
	Cluster   string                `json:"cluster,omitempty"`
	Version   uint64                `json:"version"`
	Count     int                   `json:"count"`
	Resources []resourceSourceEntry `json:"resources"`
}

var (
	sourceTypeFilter string
	sourceNameFilter string
)

// SourcesCommand queries istiod's read-only resource source index for a proxy, showing which
// Service, VirtualService, Gateway or synthesized default produced each listener/cluster/route
// and at which resource version. It never triggers a push.
func SourcesCommand(ctx cli.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sources [<type>/]<name>[.<namespace>]",
		Short: "Show the Service/VirtualService/Gateway sources and versions of a proxy's listeners, clusters and routes",
		Long: `Queries istiod (not the Envoy admin port) for the read-only resource source index of a proxy.
Each listener, cluster and route is annotated with the configuration object that produced it
(Service, VirtualService, Gateway, or an Istio default) together with that object's resource
version. Reading the index does not compute configuration or trigger a push.`,
		Example: `  # Summarize the sources of all resources for a sidecar
  istioctl proxy-config sources sleep-77ccf74cb-m6jcb.default

  # Show the origin of a single cluster
  istioctl proxy-config sources sleep-77ccf74cb-m6jcb.default --type cluster \
    --name "outbound|9080||reviews.default.svc.cluster.local"

  # Machine readable output
  istioctl proxy-config sources sleep-77ccf74cb-m6jcb.default -o json`,
		Aliases: []string{"source", "src"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Println(cmd.UsageString())
				return fmt.Errorf("sources requires a pod name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			kubeClient, err := ctx.CLIClient()
			if err != nil {
				return err
			}
			podName, podNamespace, err := getPodName(ctx, args[0])
			if err != nil {
				return err
			}
			dump, err := fetchResourceSources(ctx, kubeClient, podName, podNamespace, sourceTypeFilter, sourceNameFilter)
			if err != nil {
				return err
			}
			switch outputFormat {
			case summaryOutput:
				return printResourceSourcesSummary(cmd.OutOrStdout(), dump)
			case jsonOutput:
				return printResourceSourcesJSON(cmd.OutOrStdout(), dump)
			case yamlOutput:
				return printResourceSourcesYAML(cmd.OutOrStdout(), dump)
			default:
				return fmt.Errorf("output format %q not supported", outputFormat)
			}
		},
		ValidArgsFunction: completion.ValidPodsNameArgs(ctx),
	}
	cmd.Flags().StringVar(&sourceTypeFilter, "type", "", "Filter by resource type: one of listener|cluster|route")
	cmd.Flags().StringVar(&sourceNameFilter, "name", "", "Filter by exact Envoy resource name")
	return cmd
}

// fetchResourceSources fans out to istiod and returns the dump belonging to the requested proxy.
func fetchResourceSources(ctx cli.Context, kubeClient kube.CLIClient, podName, podNamespace, rtype, name string) (*resourceSourcesDebug, error) {
	values := url.Values{}
	values.Set("proxyID", podName+"."+podNamespace)
	values.Set("namespace", podNamespace)
	if rtype != "" {
		values.Set("type", rtype)
	}
	if name != "" {
		values.Set("name", name)
	}
	path := "debug/resource_sources?" + values.Encode()

	res, err := kubeClient.AllDiscoveryDo(context.Background(), ctx.IstioNamespace(), path)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, fmt.Errorf("no resource sources found for %s.%s: proxy is not connected to the queried istiod or has not received configuration yet",
				podName, podNamespace)
		}
		return nil, err
	}
	return selectResourceSources(res)
}

// selectResourceSources picks the dump for the connected proxy from the per-istiod responses.
// Instances that do not own the proxy answer with an empty/listing payload or non-JSON text,
// which is ignored. Exported for unit testing.
func selectResourceSources(responses map[string][]byte) (*resourceSourcesDebug, error) {
	if len(responses) == 0 {
		return nil, fmt.Errorf("no istiod instances responded")
	}
	dumps := make([]resourceSourcesDebug, 0, len(responses))
	for _, body := range responses {
		var d resourceSourcesDebug
		if err := json.Unmarshal(body, &d); err != nil {
			continue
		}
		if d.ProxyID != "" {
			dumps = append(dumps, d)
		}
	}
	switch len(dumps) {
	case 0:
		return nil, fmt.Errorf("proxy not found on any istiod instance (it may be connected to a different instance or has not received configuration)")
	case 1:
		return &dumps[0], nil
	default:
		sort.Slice(dumps, func(i, j int) bool { return dumps[i].Version > dumps[j].Version })
		return &dumps[0], nil
	}
}

func printResourceSourcesSummary(out io.Writer, d *resourceSourcesDebug) error {
	fmt.Fprintf(out, "Proxy: %s\n", d.ProxyID)
	if d.Cluster != "" {
		fmt.Fprintf(out, "Cluster: %s\n", d.Cluster)
	}
	fmt.Fprintf(out, "Index version: %d\n", d.Version)
	w := tabwriter.NewWriter(out, 0, 8, 5, ' ', 0)
	_, _ = fmt.Fprintln(w, "TYPE\tRESOURCE NAME\tSOURCE\tNAMESPACE\tVERSION\tCLUSTER")
	for _, e := range d.Resources {
		sources := e.Sources
		if len(sources) == 0 {
			sources = []resourceSource{{Kind: "default", Name: "default"}}
		}
		for _, s := range sources {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s/%s\t%s\t%s\t%s\n",
				e.Type, e.Name, s.Kind, s.Name, s.Namespace, s.Version, s.Cluster)
		}
	}
	return w.Flush()
}

func printResourceSourcesJSON(out io.Writer, d *resourceSourcesDebug) error {
	b, err := json.MarshalIndent(d, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}

func printResourceSourcesYAML(out io.Writer, d *resourceSourcesDebug) error {
	b, err := yaml.Marshal(d)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}
