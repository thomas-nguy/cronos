package ante

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/crypto-org-chain/cronos/x/cronos/keeper"
	"github.com/crypto-org-chain/cronos/x/cronos/types"
	evmante "github.com/evmos/ethermint/app/ante"
)

// NewAnteHandler add additional logic on top of Ethermint's anteHandler
func NewAnteHandler(options HandlerOptions) (sdk.AnteHandler, error) {
	return func(
		ctx sdk.Context, tx sdk.Tx, sim bool,
	) (newCtx sdk.Context, err error) {
		var anteHandler sdk.AnteHandler

		defer evmante.Recover(ctx.Logger(), &err)

		// Check msg authorization
		for _, msg := range tx.GetMsgs() {
			var permissionToCheck uint64
			var accountToCheck sdk.AccAddress

			switch v := msg.(type) {
			case *types.MsgUpdateTokenMapping:
				permissionToCheck = keeper.CanChangeTokenMapping
				acc, err := sdk.AccAddressFromBech32(v.Sender)
				if err != nil {
					panic(err)
				}
				accountToCheck = acc
				break
			case *types.MsgTurnBridge:
				permissionToCheck = keeper.CanTurnBridge
				acc, err := sdk.AccAddressFromBech32(v.Sender)
				if err != nil {
					panic(err)
				}
				accountToCheck = acc
				break
			}

			if !options.CronosKeeper.HasPermission(ctx, accountToCheck, permissionToCheck) {
				panic(sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "msg sender is authorized"))
			}
		}

		anteHandler, err = evmante.NewAnteHandler(options.EvmOptions)
		if err != nil {
			panic(err)
		}
		return anteHandler(ctx, tx, sim)
	}, nil
}
