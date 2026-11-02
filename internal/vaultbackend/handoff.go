package vaultbackend

import (
	"context"
	"encoding/json"

	enc "github.com/arctex-one/csign/v2/internal/encoding"
	"github.com/arctex-one/csign/v2/internal/faults"
	"github.com/arctex-one/csign/v2/internal/repository"
	"github.com/arctex-one/csign/v2/internal/service"
	v1 "github.com/arctex-one/csign/v2/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *Backend) custodyRoutes() []pathRegistration {
	return []pathRegistration{
		b.custodyRoute("prepare", custodyHandler(b, func(ctx context.Context, s *service.HandoffService, p v1.CustodySelection) (any, error) {
			return s.Prepare(ctx, p)
		})),
		b.custodyRoute("export", custodyHandler(b, func(ctx context.Context, s *service.HandoffService, p v1.CustodyExportRequest) (any, error) {
			return s.Export(ctx, p)
		})),
		b.custodyRoute("import", custodyHandler(b, func(ctx context.Context, s *service.HandoffService, p v1.CustodyImportRequest) (any, error) {
			return s.Import(ctx, p)
		})),
		b.custodyRoute("activate", custodyHandler(b, func(ctx context.Context, s *service.HandoffService, p v1.CustodyActivation) (any, error) {
			return s.Activate(ctx, p)
		})),
		b.custodyRoute("abort", custodyHandler(b, func(ctx context.Context, s *service.HandoffService, p v1.CustodyReference) (any, error) {
			return s.Abort(ctx, p)
		})),
		b.custodyRoute("status", custodyHandler(b, func(ctx context.Context, s *service.HandoffService, p v1.CustodyReference) (any, error) {
			return s.Status(ctx, p)
		})),
	}
}
func (*Backend) custodyRoute(action string, handler framework.OperationFunc) pathRegistration {
	route := "v1/custody/" + action
	return pathRegistration{PublicRoute: route, Path: &framework.Path{
		Pattern: route + `/?`, TakesArbitraryInput: true,
		Operations: map[logical.Operation]framework.OperationHandler{logical.UpdateOperation: &framework.PathOperation{Callback: handler, Summary: "Privileged encrypted custody handover; requires sudo capability."}},
	}}
}
func custodyHandler[T any](b *Backend, run func(context.Context, *service.HandoffService, T) (any, error)) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		b.custodyLock.Lock()
		defer b.custodyLock.Unlock()
		raw, err := json.Marshal(req.Data)
		if err != nil {
			return nil, mapError(faults.New(faults.Invalid, "invalid custody request"))
		}
		var payload T
		if enc.StrictUnmarshalJSON(raw, &payload) != nil {
			return nil, mapError(faults.New(faults.Invalid, "invalid custody request"))
		}
		result, err := run(ctx, service.NewHandoffService(repository.NewVaultKeyRepository(req.Storage, b.catalog)), payload)
		if err != nil {
			return nil, mapError(err)
		}
		return response(result), nil
	}
}
