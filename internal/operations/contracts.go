// Package operations declares Watchpost Agent's canonical operation surface.
package operations
import("github.com/gantry-tools/gantry-core/contracttest";"github.com/gantry-tools/gantry-core/operation")
var Contracts=[]operation.Contract{
	contract("watchpost-agent.status.read",operation.Read,"GET","/api/v1/status","status","get",""),
	contract("watchpost-agent.collectors.update",operation.Mutation,"PUT","/api/v1/collectors","collectors","update","watchpost-agent.collectors.updated"),
	contract("watchpost-agent.reset.apply",operation.Destructive,"POST","/api/v1/reset","reset","apply","watchpost-agent.reset.applied"),
}
func contract(id string,kind operation.Kind,method,path,resource,verb,event string)operation.Contract{audit:=operation.Audit{};if kind!=operation.Read{audit=operation.Audit{Required:true,Event:event}};return operation.Contract{SchemaVersion:operation.SchemaVersion,ID:id,Kind:kind,Route:operation.Route{Method:method,Path:path},CLI:&operation.CLI{Resource:resource,Verb:verb},Authorization:operation.Authorization{Boundary:operation.Session},Audit:audit,Idempotency:operation.Idempotency{RetrySafe:kind==operation.Read},Automation:operation.Automatable}}
func AdoptionManifest()contracttest.Manifest{routes:=make([]operation.Route,len(Contracts));ids:=make([]string,len(Contracts));for i,c:=range Contracts{routes[i],ids[i]=c.Route,c.ID};return contracttest.Manifest{SchemaVersion:1,Project:"watchpost-agent",Operations:Contracts,ObservedRoutes:routes,WebsiteOperations:ids}}
