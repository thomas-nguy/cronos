package evidenceage

import (
	"context"

	"cosmossdk.io/x/evidence"
	evidencekeeper "cosmossdk.io/x/evidence/keeper"
	evidencetypes "cosmossdk.io/x/evidence/types"

	"github.com/cosmos/cosmos-sdk/telemetry"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AppModule wraps the stock evidence AppModule and overrides BeginBlock to
// skip all equivocation handling (no slash/jail/tombstone). Temporary recovery
// build after a coordinated rollback — deploy on all validators, then revert.
type AppModule struct {
	evidence.AppModule

	evidenceKeeper evidencekeeper.Keeper
}

// NewAppModule creates an evidence AppModule that does not apply misbehavior evidence.
func NewAppModule(evidenceKeeper evidencekeeper.Keeper) AppModule {
	return AppModule{
		AppModule:      evidence.NewAppModule(evidenceKeeper),
		evidenceKeeper: evidenceKeeper,
	}
}

// BeginBlock ignores all CometBFT misbehavior evidence so nothing is slashed.
func (am AppModule) BeginBlock(ctx context.Context) error {
	defer telemetry.ModuleMeasureSince(evidencetypes.ModuleName, telemetry.Now(), telemetry.MetricKeyBeginBlocker)

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	bi := sdkCtx.CometInfo()
	if bi == nil {
		return nil
	}

	n := bi.GetEvidence().Len()
	if n > 0 {
		am.evidenceKeeper.Logger(sdkCtx).Info(
			"ignored all equivocation evidence; slashing disabled for recovery",
			"num_evidence", n,
		)
	}
	return nil
}
