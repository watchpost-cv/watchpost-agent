// Package operations declares Watchpost Agent's canonical functional HTTP surface.
package operations

import (
	"github.com/gantry-tools/gantry-core/contracttest"
	"github.com/gantry-tools/gantry-core/operation"
)

type spec struct {
	id, method, path, resource, verb, capability, test string
	kind                                               operation.Kind
	boundary                                           operation.Boundary
	website                                            bool
	secrets                                            []string
}

var specs = []spec{
	{"watchpost-agent.health.get", "GET", "/healthz", "health", "get", "", "internal/app/app_test.go", operation.Read, operation.Public, false, nil},
	{"watchpost-agent.ready.get", "GET", "/readyz", "ready", "get", "", "internal/app/app_test.go", operation.Read, operation.Public, false, nil},
	{"watchpost-agent.auth.bootstrap", "GET", "/api/v1/bootstrap", "auth", "bootstrap", "", "internal/app/app_test.go", operation.Read, operation.Public, true, nil},
	{"watchpost-agent.auth.setup", "POST", "/api/v1/setup", "auth", "setup", "", "internal/app/app_test.go", operation.Mutation, operation.Public, true, []string{"/password"}},
	{"watchpost-agent.auth.login", "POST", "/api/v1/login", "auth", "login", "", "internal/app/app_test.go", operation.Mutation, operation.Public, true, []string{"/password"}},
	{"watchpost-agent.auth.logout", "POST", "/api/v1/logout", "auth", "logout", "watchpost-agent.role.viewer", "internal/app/app_test.go", operation.Destructive, operation.Capability, true, nil},
	{"watchpost-agent.status.get", "GET", "/api/v1/status", "status", "get", "watchpost-agent.role.viewer", "internal/app/app_test.go", operation.Read, operation.Capability, true, nil},
	{"watchpost-agent.pairing.request", "POST", "/api/v1/pairing/request", "pairing", "request", "watchpost-agent.role.technician", "internal/app/app_test.go", operation.Mutation, operation.Capability, true, nil},
	{"watchpost-agent.pairing.poll", "POST", "/api/v1/pairing/poll", "pairing", "poll", "watchpost-agent.role.technician", "internal/app/app_test.go", operation.Mutation, operation.Capability, true, nil},
	{"watchpost-agent.collectors.list", "GET", "/api/v1/collectors", "collectors", "list", "watchpost-agent.role.viewer", "internal/app/app_test.go", operation.Read, operation.Capability, true, nil},
	{"watchpost-agent.collectors.update", "PUT", "/api/v1/collectors", "collectors", "update", "watchpost-agent.role.technician", "internal/app/app_test.go", operation.Mutation, operation.Capability, true, nil},
	{"watchpost-agent.connection.unpair", "POST", "/api/v1/unpair", "connection", "unpair", "watchpost-agent.role.admin", "internal/app/app_test.go", operation.Destructive, operation.Capability, true, nil},
	{"watchpost-agent.connection.rotate", "POST", "/api/v1/rotate", "connection", "rotate", "watchpost-agent.role.admin", "internal/app/app_test.go", operation.Mutation, operation.Capability, true, nil},
	{"watchpost-agent.agent.reset", "POST", "/api/v1/reset", "agent", "reset", "watchpost-agent.role.admin", "internal/app/app_test.go", operation.Destructive, operation.Capability, true, nil},
	{"watchpost-agent.auth.password.update", "POST", "/api/v1/me/password", "auth-password", "update", "watchpost-agent.role.viewer", "internal/app/app_test.go", operation.Mutation, operation.Capability, true, []string{"/password"}},
	{"watchpost-agent.accounts.list", "GET", "/api/v1/accounts", "accounts", "list", "watchpost-agent.role.admin", "internal/app/app_test.go", operation.Read, operation.Capability, true, nil},
	{"watchpost-agent.accounts.create", "POST", "/api/v1/accounts", "accounts", "create", "watchpost-agent.role.admin", "internal/app/app_test.go", operation.Mutation, operation.Capability, true, []string{"/password"}},
	{"watchpost-agent.accounts.revoke-sessions", "POST", "/api/v1/accounts/{id}/revoke-sessions", "accounts", "revoke-sessions", "watchpost-agent.role.admin", "internal/app/app_test.go", operation.Destructive, operation.Capability, true, nil},
	{"watchpost-agent.audit.list", "GET", "/api/v1/audit", "audit", "list", "watchpost-agent.role.admin", "internal/app/app_test.go", operation.Read, operation.Capability, true, nil},
	{"watchpost-agent.launcher.instances.list", "GET", "/api/launcher/instances", "launcher-instances", "list", "", "internal/app/app_test.go", operation.Read, operation.Public, true, nil},
	{"watchpost-agent.launcher.config.update", "PUT", "/api/launcher/config", "launcher-config", "update", "watchpost-agent.role.admin", "internal/app/app_test.go", operation.Mutation, operation.Capability, true, nil},
}

var Contracts = buildContracts()

func buildContracts() []operation.Contract {
	out := make([]operation.Contract, 0, len(specs))
	for _, s := range specs {
		var cli *operation.CLI
		if s.resource != "" {
			cli = &operation.CLI{Resource: s.resource, Verb: s.verb, Implemented: true}
		}
		audit := operation.Audit{}
		if s.kind != operation.Read {
			audit = operation.Audit{Required: true, Event: s.id + ".performed"}
		}
		schemas := operation.Schemas{Output: s.id + ".response.v1"}
		if s.kind != operation.Read {
			schemas.Input = s.id + ".request.v1"
		}
		out = append(out, operation.Contract{SchemaVersion: operation.SchemaVersion, ID: s.id, Kind: s.kind, Route: operation.Route{Method: s.method, Path: s.path}, CLI: cli, Authorization: operation.Authorization{Boundary: s.boundary, Capability: s.capability}, Schemas: schemas, Audit: audit, Idempotency: operation.Idempotency{RetrySafe: s.kind == operation.Read}, Automation: operation.Automatable, SecretInputs: s.secrets})
	}
	return out
}

func Manifest() contracttest.Manifest {
	routes := make([]operation.Route, 0, len(Contracts))
	commands := make([]operation.CLI, 0, len(Contracts))
	website := make([]string, 0, len(Contracts))
	evidence := map[string]contracttest.Evidence{}
	for i, c := range Contracts {
		routes = append(routes, c.Route)
		if c.CLI != nil && c.CLI.Implemented {
			commands = append(commands, *c.CLI)
		}
		if specs[i].website {
			website = append(website, c.ID)
		}
		evidence[c.ID] = contracttest.Evidence{Website: specs[i].website, Tests: []string{specs[i].test}}
	}
	return contracttest.Manifest{SchemaVersion: 1, Project: "watchpost-agent", Operations: Contracts, ObservedRoutes: routes, ObservedCommands: commands, WebsiteOperations: website, Evidence: evidence}
}
func AdoptionManifest() contracttest.Manifest { return Manifest() }
