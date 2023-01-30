package ibctest

import (
	"context"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	transfertypes "github.com/cosmos/ibc-go/v5/modules/apps/transfer/types"
	"github.com/cosmos/relayer/v2/relayer"
	"github.com/cosmos/relayer/v2/relayer/processor"
	ibctestv5 "github.com/strangelove-ventures/ibctest/v5"
	"github.com/strangelove-ventures/ibctest/v5/ibc"
	"github.com/strangelove-ventures/ibctest/v5/test"
	"github.com/strangelove-ventures/ibctest/v5/testreporter"
	"github.com/strangelove-ventures/lens/client"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"
)

// TestScenarioFeegrantBasic Feegrant on a single chain
// Run this test with e.g. go test -timeout 300s -run ^TestScenarioFeegrantBasic$ github.com/cosmos/relayer/v2/ibctest
func TestScenarioFeegrantBasic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	nv := 1
	nf := 0

	// Chain Factory
	cf := ibctestv5.NewBuiltinChainFactory(zaptest.NewLogger(t), []*ibctestv5.ChainSpec{
		{Name: "gaia", Version: "v7.0.3", NumValidators: &nv, NumFullNodes: &nf},
		{Name: "osmosis", Version: "v11.0.1", NumValidators: &nv, NumFullNodes: &nf},
	})

	chains, err := cf.Chains(t.Name())
	require.NoError(t, err)
	gaia, osmosis := chains[0], chains[1]

	// Relayer Factory to construct relayer
	r := NewRelayerFactory(RelayerConfig{
		Processor:           relayer.ProcessorEvents,
		InitialBlockHistory: 100,
	}).Build(t, nil, "")

	// Prep Interchain
	const ibcPath = "gaia-osmosis"
	ic := ibctestv5.NewInterchain().
		AddChain(gaia).
		AddChain(osmosis).
		AddRelayer(r, "relayer").
		AddLink(ibctestv5.InterchainLink{
			Chain1:  gaia,
			Chain2:  osmosis,
			Relayer: r,
			Path:    ibcPath,
		})

	// Reporter/logs
	rep := testreporter.NewNopReporter()
	eRep := rep.RelayerExecReporter(t)

	client, network := ibctestv5.DockerSetup(t)

	// Build interchain
	require.NoError(t, ic.Build(ctx, eRep, ibctestv5.InterchainBuildOptions{
		TestName:  t.Name(),
		Client:    client,
		NetworkID: network,

		SkipPathCreation: false,
	}))

	// Get Channel ID
	gaiaChans, err := r.GetChannels(ctx, eRep, gaia.Config().ChainID)
	require.NoError(t, err)
	gaiaChannel := gaiaChans[0]
	osmosisChannel := gaiaChans[0].Counterparty

	r.UpdatePath(ctx, eRep, ibcPath, ibc.ChannelFilter{
		Rule:        processor.RuleAllowList,
		ChannelList: []string{gaiaChannel.ChannelID},
	})

	// Create and Fund User Wallets
	fundAmount := int64(10_000_000)
	// Tiny amount of funding, not even enough to pay for a single TX fee (that is the whole point - the GRANTER should be paying the fee)
	granteeFundAmount := int64(10)

	//Mnemonic from the juno repo test user
	granterMnemonic := "clip hire initial neck maid actor venue client foam budget lock catalog sweet steak waste crater broccoli pipe steak sister coyote moment obvious choose"
	granterUsers := GetAndFundTestUsers(t, ctx, "default", granterMnemonic, int64(fundAmount), gaia, osmosis)
	fundRecipientUsers := GetAndFundTestUsers(t, ctx, "recipient", "", int64(fundAmount), gaia, osmosis)
	gaiaGranterUser, osmosisGranterUser := granterUsers[0], granterUsers[1]
	gaiaRecipient, osmosisRecipient := fundRecipientUsers[0], fundRecipientUsers[1]

	usersGrantees := GetAndFundTestUsers(t, ctx, "grantee1", "", int64(granteeFundAmount), gaia)
	gaiaGrantee := usersGrantees[0]

	r.StartRelayer(ctx, eRep, ibcPath)
	logger := zaptest.NewLogger(t)

	//TODO: why is this necessary? How do we link chain config to RELAYER config?
	if err := r.RestoreKey(ctx,
		eRep,
		gaia.Config().ChainID, gaiaGranterUser.KeyName,
		granterMnemonic,
	); err != nil {
		t.Fatalf("failed to restore key to relayer for chain %s: %s", gaia.Config().ChainID, err.Error())
	}

	localRelayer := r.(*Relayer)
	res := localRelayer.sys().Run(logger, "chains", "configure", "feegrant", "basicallowance", gaia.Config().Name, gaiaGranterUser.KeyName, "--grantees", "10", "--overwrite-grantees")
	if res.Err != nil {
		t.Fatalf("failed to rly config feegrants: %v", res.Err)
	}

	// Send Transaction
	amountToSend := int64(1_000)
	gaiaDstAddress := gaiaRecipient.Bech32Address(osmosis.Config().Bech32Prefix)
	osmosisDstAddress := osmosisRecipient.Bech32Address(gaia.Config().Bech32Prefix)

	gaiaGranteeAddr := gaiaGrantee.Bech32Address(gaia.Config().Bech32Prefix)
	gaiaGranterAddr := gaiaGranterUser.Bech32Address(gaia.Config().Bech32Prefix)

	gaiaHeight, err := gaia.Height(ctx)
	require.NoError(t, err)

	osmosisHeight, err := osmosis.Height(ctx)
	require.NoError(t, err)

	var eg errgroup.Group
	eg.Go(func() error {
		tx, err := gaia.SendIBCTransfer(ctx, gaiaChannel.ChannelID, gaiaGranterUser.KeyName, ibc.WalletAmount{
			Address: gaiaDstAddress,
			Denom:   gaia.Config().Denom,
			Amount:  amountToSend,
		},
			nil,
		)
		if err != nil {
			return err
		}
		if err := tx.Validate(); err != nil {
			return err
		}
		_, err = test.PollForAck(ctx, gaia, gaiaHeight, gaiaHeight+10, tx.Packet)
		return err
	})

	eg.Go(func() error {
		tx, err := osmosis.SendIBCTransfer(ctx, osmosisChannel.ChannelID, osmosisGranterUser.KeyName, ibc.WalletAmount{
			Address: osmosisDstAddress,
			Denom:   osmosis.Config().Denom,
			Amount:  amountToSend,
		},
			nil,
		)
		if err != nil {
			return err
		}
		if err := tx.Validate(); err != nil {
			return err
		}
		_, err = test.PollForAck(ctx, osmosis, osmosisHeight, osmosisHeight+10, tx.Packet)
		return err
	})
	// Acks should exist
	require.NoError(t, eg.Wait())

	// Trace IBC Denom
	gaiaDenomTrace := transfertypes.ParseDenomTrace(transfertypes.GetPrefixedDenom(osmosisChannel.PortID, osmosisChannel.ChannelID, gaia.Config().Denom))
	gaiaIbcDenom := gaiaDenomTrace.IBCDenom()

	osmosisDenomTrace := transfertypes.ParseDenomTrace(transfertypes.GetPrefixedDenom(gaiaChannel.PortID, gaiaChannel.ChannelID, osmosis.Config().Denom))
	osmosisIbcDenom := osmosisDenomTrace.IBCDenom()

	// Test destination wallets have increased funds
	gaiaIBCBalance, err := osmosis.GetBalance(ctx, gaiaDstAddress, gaiaIbcDenom)
	require.NoError(t, err)
	require.Equal(t, amountToSend, gaiaIBCBalance)

	osmosisIBCBalance, err := gaia.GetBalance(ctx, osmosisDstAddress, osmosisIbcDenom)
	require.NoError(t, err)
	require.Equal(t, amountToSend, osmosisIBCBalance)

	// Test grantee still has exact amount expected
	gaiaGranteeIBCBalance, err := gaia.GetBalance(ctx, gaiaGranteeAddr, gaiaIbcDenom)
	require.NoError(t, err)
	require.Equal(t, granteeFundAmount, gaiaGranteeIBCBalance)

	// Test granter has less than they started with, meaning fees came from their account
	gaiaGranterIBCBalance, err := gaia.GetBalance(ctx, gaiaGranterAddr, gaiaIbcDenom)
	require.NoError(t, err)
	require.Less(t, gaiaGranterIBCBalance, fundAmount)
}

func fundAccount(t *testing.T, ctx context.Context, cc *client.ChainClient, keyNameReceiveFunds string, keyNameSendFunds string, amountCoin string, gas uint64) string {
	fromAddr, err := cc.GetKeyAddressForKey(keyNameSendFunds)
	if err != nil {
		t.Fatal(err)
	}

	toAddr, err := cc.GetKeyAddressForKey(keyNameReceiveFunds)
	if err != nil {
		t.Fatal(err)
	}

	coins, err := sdk.ParseCoinsNormalized(amountCoin)
	if err != nil {
		t.Fatal(err)
	}

	req := &banktypes.MsgSend{
		FromAddress: cc.MustEncodeAccAddr(fromAddr),
		ToAddress:   cc.MustEncodeAccAddr(toAddr),
		Amount:      coins,
	}

	res, err := cc.SubmitTxAwaitResponse(ctx, []sdk.Msg{req}, "", gas, keyNameSendFunds)
	if err != nil {
		t.Fatal(err)
	}
	return res.TxResponse.TxHash
}
