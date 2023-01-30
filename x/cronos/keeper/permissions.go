package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/crypto-org-chain/cronos/v2/x/cronos/types"
)

// A permission is represented by a bit within uint64 (64bits)
// An address permission is an integer value between 0 and (2^64-1)
// This design allows a quick and simple permission check for addresses
// The next permission should be added before All
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)

func (k Keeper) SetPermissions(ctx sdk.Context, address sdk.AccAddress, permissions uint64) {
	store := ctx.KVStore(k.storeKey)
	permissionsBytes := sdk.Uint64ToBigEndian(permissions)
	store.Set(types.AdminToPermissionsKey(address), permissionsBytes)
}

func (k Keeper) GetPermissions(ctx sdk.Context, address sdk.AccAddress) uint64 {
	store := ctx.KVStore(k.storeKey)
	permissionsBytes := store.Get(types.AdminToPermissionsKey(address))
	return sdk.BigEndianToUint64(permissionsBytes)
}

// HasPermission check if an account has a specific permission. by default cronos admin has all permissions
func (k Keeper) HasPermission(ctx sdk.Context, account sdk.AccAddress, permissionsToCheck uint64) bool {
	admin := k.GetParams(ctx).CronosAdmin
	permission := k.GetPermissions(ctx, account)
	mask := permission & permissionsToCheck
	return (admin == account.String()) || (mask == permissionsToCheck)
}
