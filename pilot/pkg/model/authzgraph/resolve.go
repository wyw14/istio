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

package authzgraph

import (
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
)

// Registry aliases used by targetRef resolution; a core Service lives in the
// Kubernetes registry and a ServiceEntry in the External registry, mirroring
// model.WorkloadPolicyMatcher.
var (
	providerKubernetes = provider.Kubernetes
	providerExternal   = provider.External
)

// revLabel is the revision pinning label on Istio resources.
const revLabel = "istio.io/rev"

func (b *builder) serviceExists(namespace, name string, registry provider.ID) bool {
	for _, s := range b.in.Services {
		if s.Namespace == namespace && s.Name == name && s.Registry == registry {
			return true
		}
	}
	return false
}

func (b *builder) gatewayExists(namespace, name string) bool {
	for _, g := range b.in.Gateways {
		if g.Namespace == namespace && g.Name == name {
			return true
		}
	}
	return false
}

func (b *builder) gatewayClassExists(name string) bool {
	for _, c := range b.in.GatewayClasses {
		if c == name {
			return true
		}
	}
	return false
}

func (b *builder) httpRouteExists(namespace, name string) bool {
	for _, r := range b.in.HTTPRoutes {
		if r.Namespace == namespace && r.Name == name {
			return true
		}
	}
	return false
}
