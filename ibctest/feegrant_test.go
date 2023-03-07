package ibctest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	ante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	transfertypes "github.com/cosmos/ibc-go/v5/modules/apps/transfer/types"
	"github.com/cosmos/relayer/v2/relayer"
	"github.com/cosmos/relayer/v2/relayer/chains/cosmos"
	"github.com/cosmos/relayer/v2/relayer/processor"
	ibctestv5 "github.com/strangelove-ventures/ibctest/v5"
	"github.com/strangelove-ventures/ibctest/v5/ibc"
	"github.com/strangelove-ventures/ibctest/v5/test"
	"github.com/strangelove-ventures/ibctest/v5/testreporter"
	"github.com/strangelove-ventures/lens/client"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"
)

// protoTxProvider is a type which can provide a proto transaction. It is a
// workaround to get access to the wrapper TxBuilder's method GetProtoTx().
type protoTxProvider interface {
	GetProtoTx() *txtypes.Tx
}

type chainFeegrantInfo struct {
	granter    string
	grantees   []string
	lastSigner string //whichever grantee signed the last known TX on chain
}

func nextGrantee(gi *chainFeegrantInfo) string {
	for i, grantee := range gi.grantees {
		if gi.lastSigner == grantee && i < len(gi.grantees)-1 {
			return gi.grantees[i+1]
		} else if gi.lastSigner == grantee {
			return gi.grantees[0]
		}
	}

	return gi.grantees[0]
}

// TestScenarioFeegrantBasic Feegrant on a single chain
// Run this test with e.g. go test -timeout 300s -run ^TestScenarioFeegrantBasic$ github.com/cosmos/relayer/v2/ibctest.
//
// Helpful to debug:
// docker ps -a --format {{.Names}} then e.g. docker logs gaia-1-val-0-TestScenarioFeegrantBasic 2>&1 -f
func TestScenarioFeegrantBasic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	logger := zaptest.NewLogger(t)
	ante.Logger = logger

	nv := 1
	nf := 0

	//In order to have this image locally you'd need to build it with heighliner, e.g.,
	//from within the local "gaia" directory, run the following command:
	//../heighliner/heighliner build -c gaia --local -f ../heighliner/chains.yaml
	gaiaImage := ibc.DockerImage{
		Repository: "gaia",
		Version:    "local",
		UidGid:     "1025:1025", //the heighliner user string. this isn't exposed on ibctest
	}

	gaiaChainSpec := &ibctestv5.ChainSpec{
		ChainName:     "gaia",
		NumValidators: &nv,
		NumFullNodes:  &nf,
		ChainConfig: ibc.ChainConfig{
			Type: "cosmos",
			Name: "gaia",
			//ChainID:        "gaia-1", //I believe this will be auto-generated?
			Images:         []ibc.DockerImage{gaiaImage},
			Bin:            "gaiad",
			Bech32Prefix:   "cosmos",
			Denom:          "uatom",
			GasPrices:      "0.01uatom",
			TrustingPeriod: "504h",
			GasAdjustment:  1.3,
		}}

	// Chain Factory
	cf := ibctestv5.NewBuiltinChainFactory(zaptest.NewLogger(t), []*ibctestv5.ChainSpec{
		//{Name: "gaia", ChainName: "gaia", Version: "v7.0.3", NumValidators: &nv, NumFullNodes: &nf},
		gaiaChainSpec,
		{Name: "osmosis", ChainName: "osmosis", Version: "v14.0.1", NumValidators: &nv, NumFullNodes: &nf},
	})

	chains, err := cf.Chains(t.Name())
	require.NoError(t, err)
	gaia, osmosis := chains[0], chains[1]

	// Relayer Factory to construct relayer
	r := NewRelayerFactory(RelayerConfig{
		Processor:           relayer.ProcessorEvents,
		InitialBlockHistory: 100,
	}).Build(t, nil, "")

	processor.PathProcMessageCollector = make(chan *processor.PathProcessorMessageResp, 50)

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

	// r.UpdatePath(ctx, eRep, ibcPath, ibc.ChannelFilter{
	// 	Rule:        processor.RuleAllowList,
	// 	ChannelList: []string{gaiaChannel.ChannelID},
	// })

	// Create and Fund User Wallets
	fundAmount := int64(10_000_000)
	// Tiny amount of funding, not even enough to pay for a single TX fee (that is the whole point - the GRANTER should be paying the fee)
	granteeFundAmount := int64(10)

	//Mnemonic from the juno repo test user
	gaiaGranterMnemonic := "clip hire initial neck maid actor venue client foam budget lock catalog sweet steak waste crater broccoli pipe steak sister coyote moment obvious choose"

	//Other made up mnemonics. Local testnet only.
	osmosisGranterMnemonic := "deal faint choice forward valid practice secret lava harbor stadium train view improve tide cook sadness juice trap mansion smooth erupt version parrot canvas"
	gaiaGranteeMnemonic := "unusual car spray work spread column badge radar oxygen oblige roof patrol wheel sing damage advice flower forest segment park blue defense morning manage"
	gaiaGrantee2Mnemonic := "little pumpkin glimpse initial manual wool relief coach violin main sheriff law virtual inmate inmate mixture erode funny garbage kangaroo wait leave cloth climb"
	gaiaGrantee3Mnemonic := "pattern custom brand child fatal three body food fee soul gesture armor increase dynamic enforce vintage borrow admit slot gold affair rubber tide lava"
	osmosisGranteeMnemonic := "flight toilet early leaf hen dragon story relief indoor gap shoot firm topple start where illegal paper risk insect neutral busy olympic glory evoke"
	ibcTransferMnemonic := "flight toilet early leaf hen dragon story relief indoor gap shoot firm topple start where illegal paper risk insect neutral busy olympic glory evoke"

	granteeKey := "grantee1"
	grantee2Key := "grantee2"
	grantee3Key := "grantee3"
	granterKey := "default"

	//IBC chain config is unrelated to RELAYER config so this step is necessary
	if err := r.RestoreKey(ctx,
		eRep,
		gaia.Config().ChainID, granterKey,
		gaiaGranterMnemonic,
	); err != nil {
		t.Fatalf("failed to restore granter key to relayer for chain %s: %s", gaia.Config().ChainID, err.Error())
	}

	//IBC chain config is unrelated to RELAYER config so this step is necessary
	if err := r.RestoreKey(ctx,
		eRep,
		gaia.Config().ChainID, granteeKey,
		gaiaGranteeMnemonic,
	); err != nil {
		t.Fatalf("failed to restore granter key to relayer for chain %s: %s", gaia.Config().ChainID, err.Error())
	}

	//IBC chain config is unrelated to RELAYER config so this step is necessary
	if err := r.RestoreKey(ctx,
		eRep,
		gaia.Config().ChainID, grantee2Key,
		gaiaGrantee2Mnemonic,
	); err != nil {
		t.Fatalf("failed to restore granter key to relayer for chain %s: %s", gaia.Config().ChainID, err.Error())
	}

	//IBC chain config is unrelated to RELAYER config so this step is necessary
	if err := r.RestoreKey(ctx,
		eRep,
		gaia.Config().ChainID, grantee3Key,
		gaiaGrantee3Mnemonic,
	); err != nil {
		t.Fatalf("failed to restore granter key to relayer for chain %s: %s", gaia.Config().ChainID, err.Error())
	}

	//IBC chain config is unrelated to RELAYER config so this step is necessary
	if err := r.RestoreKey(ctx,
		eRep,
		osmosis.Config().ChainID, granterKey,
		osmosisGranterMnemonic,
	); err != nil {
		t.Fatalf("failed to restore granter key to relayer for chain %s: %s", osmosis.Config().ChainID, err.Error())
	}

	//IBC chain config is unrelated to RELAYER config so this step is necessary
	if err := r.RestoreKey(ctx,
		eRep,
		osmosis.Config().ChainID, granteeKey,
		osmosisGranteeMnemonic,
	); err != nil {
		t.Fatalf("failed to restore granter key to relayer for chain %s: %s", gaia.Config().ChainID, err.Error())
	}

	gaiaGranter := GetAndFundTestUsers(t, ctx, granterKey, gaiaGranterMnemonic, int64(fundAmount), gaia)[0]
	osmosisGranter := GetAndFundTestUsers(t, ctx, granterKey, osmosisGranterMnemonic, int64(fundAmount), osmosis)[0]
	gaiaGrantee := GetAndFundTestUsers(t, ctx, granteeKey, gaiaGranteeMnemonic, int64(granteeFundAmount), gaia)[0]
	gaiaGrantee2 := GetAndFundTestUsers(t, ctx, grantee2Key, gaiaGrantee2Mnemonic, int64(granteeFundAmount), gaia)[0]
	gaiaGrantee3 := GetAndFundTestUsers(t, ctx, grantee3Key, gaiaGrantee3Mnemonic, int64(granteeFundAmount), gaia)[0]
	osmosisGrantee := GetAndFundTestUsers(t, ctx, granteeKey, osmosisGranteeMnemonic, int64(granteeFundAmount), osmosis)[0]
	osmosisRecipient := GetAndFundTestUsers(t, ctx, "recipient", "", int64(fundAmount), osmosis)
	gaiaRecipient := GetAndFundTestUsers(t, ctx, "recipient", ibcTransferMnemonic, int64(fundAmount), gaia)
	osmosisUser := osmosisRecipient[0]
	gaiaUser := gaiaRecipient[0]

	gaiaGranteeAddr := gaiaGrantee.Bech32Address(gaia.Config().Bech32Prefix)
	gaiaGrantee2Addr := gaiaGrantee2.Bech32Address(gaia.Config().Bech32Prefix)
	gaiaGrantee3Addr := gaiaGrantee3.Bech32Address(gaia.Config().Bech32Prefix)
	gaiaGranterAddr := gaiaGranter.Bech32Address(gaia.Config().Bech32Prefix)
	gaiaUserAddr := gaiaUser.Bech32Address(gaia.Config().Bech32Prefix)
	osmoGranteeAddr := osmosisGrantee.Bech32Address(osmosis.Config().Bech32Prefix)
	osmoGranterAddr := osmosisGranter.Bech32Address(osmosis.Config().Bech32Prefix)

	fmt.Printf("Gaia grantee address %s,gaia grantee key %s", gaiaGranteeAddr, gaiaGrantee.KeyName)
	fmt.Printf("Gaia granter address %s,gaia granter key %s", gaiaGranterAddr, gaiaGranter.KeyName)
	fmt.Printf("Gaia user address %s, gaia user key %s", gaiaUserAddr, gaiaUser.KeyName)

	logger.Debug("Key address", zap.String("osmosis grantee", osmoGranteeAddr), zap.String("osmosis grantee key", osmosisGrantee.KeyName))
	logger.Debug("Key address", zap.String("osmosis granter", osmoGranterAddr), zap.String("osmosis granter key", osmosisGranter.KeyName))

	granteeCsv := gaiaGrantee.KeyName + "," + gaiaGrantee2.KeyName + "," + gaiaGrantee3.KeyName

	//You MUST run the configure feegrant command prior to starting the relayer, otherwise it'd be like you never set it up at all (within this test)
	//Note that Gaia supports feegrants, but Osmosis does not (x/feegrant module, or any compatible module, is not included in Osmosis SDK app modules)
	localRelayer := r.(*Relayer)
	res := localRelayer.sys().Run(logger, "chains", "configure", "feegrant", "basicallowance", gaia.Config().ChainID, gaiaGranter.KeyName, "--grantees", granteeCsv, "--overwrite-granter")
	if res.Err != nil {
		fmt.Printf("configure feegrant results: %s\n", res.Stdout.String())
		t.Fatalf("failed to rly config feegrants: %v", res.Err)
	}

	//Map of feegranted chains and the feegrant info for the chain
	feegrantedChains := map[string]*chainFeegrantInfo{}
	feegrantedChains[gaia.Config().ChainID] = &chainFeegrantInfo{granter: gaiaGranterAddr, grantees: []string{gaiaGranteeAddr, gaiaGrantee2Addr, gaiaGrantee3Addr}}

	time.Sleep(7 * time.Second) //commit a block
	r.StartRelayer(ctx, eRep, ibcPath)

	// Send Transaction
	amountToSend := int64(1_000)
	gaiaDstAddress := gaiaUser.Bech32Address(osmosis.Config().Bech32Prefix)
	osmosisDstAddress := osmosisUser.Bech32Address(gaia.Config().Bech32Prefix)

	gaiaHeight, err := gaia.Height(ctx)
	require.NoError(t, err)

	osmosisHeight, err := osmosis.Height(ctx)
	require.NoError(t, err)

	fmt.Printf("Before send ibc transfer")

	var eg errgroup.Group
	var gaiaTx ibc.Tx

	eg.Go(func() error {
		gaiaTx, err = gaia.SendIBCTransfer(ctx, gaiaChannel.ChannelID, gaiaUser.KeyName, ibc.WalletAmount{
			Address: gaiaDstAddress,
			Denom:   gaia.Config().Denom,
			Amount:  amountToSend,
		},
			nil,
		)
		if err != nil {
			return err
		}
		if err := gaiaTx.Validate(); err != nil {
			return err
		}

		// gaiaCC := gaia.(*ibcCosmos.CosmosChain)
		// txResp, err := gaiaCC.GetTransaction(tx.TxHash)
		// if err != nil {
		// 	return err
		// }
		// for _, evt := range txResp.Events {
		// 	logger.Debug("TX EVENT", zap.String("type", evt.Type))
		// 	for _, attr := range evt.Attributes {
		// 		logger.Debug("TX EVENT ATTR", zap.String("attr key", string(attr.Key)), zap.String("attr val", string(attr.Value)))
		// 	}
		// }

		_, err = test.PollForAck(ctx, gaia, gaiaHeight, gaiaHeight+10, gaiaTx.Packet)
		return err
	})

	eg.Go(func() error {
		tx, err := osmosis.SendIBCTransfer(ctx, osmosisChannel.ChannelID, osmosisUser.KeyName, ibc.WalletAmount{
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

	eg.Go(func() error {
		tx, err := osmosis.SendIBCTransfer(ctx, osmosisChannel.ChannelID, osmosisUser.KeyName, ibc.WalletAmount{
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

	eg.Go(func() error {
		tx, err := osmosis.SendIBCTransfer(ctx, osmosisChannel.ChannelID, osmosisUser.KeyName, ibc.WalletAmount{
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

	require.NoError(t, err)
	require.NoError(t, eg.Wait())

	r.StopRelayer(ctx, eRep)

	for len(processor.PathProcMessageCollector) > 0 {
		select {
		case curr, ok := <-processor.PathProcMessageCollector:
			if ok && curr.Error == nil && curr.SuccessfulTx {
				cProv := curr.DestinationChain.(*cosmos.CosmosProvider)
				lensClient := cProv.ChainClient
				chain := lensClient.Config.ChainID
				feegrantInfo, isFeegrantedChain := feegrantedChains[chain]

				// if isFeegrantedChain {
				// 	require.Greater(t, cProv.PCfg.FeeGrants.BlockHeightVerified, 0)
				// }

				sdkConf := sdk.GetConfig()
				sdkConf.SetBech32PrefixForAccount(lensClient.Config.AccountPrefix, lensClient.Config.AccountPrefix+"pub")
				sdkConf.SetBech32PrefixForValidator(lensClient.Config.AccountPrefix+"valoper", lensClient.Config.AccountPrefix+"valoperpub")
				sdkConf.SetBech32PrefixForConsensusNode(lensClient.Config.AccountPrefix+"valcons", lensClient.Config.AccountPrefix+"valconspub")

				txResp, err := lensClient.QueryTx(ctx, curr.Response.TxHash, false)

				require.Nil(t, err)
				dc := lensClient.Codec.TxConfig.TxDecoder()
				tx, err := dc(txResp.Tx)
				require.Nil(t, err)
				builder, err := lensClient.Codec.TxConfig.WrapTxBuilder(tx)
				require.Nil(t, err)
				txFinder := builder.(protoTxProvider)
				fullTx := txFinder.GetProtoTx()
				isFeegrantedMsg := false

				msgType := ""
				for _, m := range fullTx.GetMsgs() {
					msgType = types.MsgTypeURL(m)
					//We want all IBC transfers (on an open channel/connection) to be feegranted in round robin fashion
					if msgType == "/ibc.core.channel.v1.MsgRecvPacket" || msgType == "/ibc.core.channel.v1.MsgAcknowledgement" {
						isFeegrantedMsg = true
						break
					}
				}

				//It's required that TXs be feegranted in a round robin fashion for this chain and message type
				if isFeegrantedChain && isFeegrantedMsg {
					signers := fullTx.GetSigners()
					require.Equal(t, len(signers), 1)
					granter := fullTx.FeeGranter()

					//Feegranter for the TX that was signed on chain must be the relayer chain's configured feegranter
					require.Equal(t, granter.String(), feegrantInfo.granter)
					require.NotEmpty(t, granter)

					//Grantee for the TX that was signed on chain must be a configured grantee in the relayer's chain feegrants.
					//In addition, the grantee must be used in round robin fashion
					expectedGrantee := nextGrantee(feegrantInfo)
					actualGrantee := signers[0].String()
					fmt.Printf("Chain: %s, msg type: %s, height: %d, signer: %s, granter: %s\n", chain, msgType, curr.Response.Height, actualGrantee, granter.String())
					require.Equal(t, expectedGrantee, actualGrantee)
					feegrantInfo.lastSigner = actualGrantee
				}
			}
		default:
			fmt.Println("Unknown channel message")
		}
	}

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
	require.Equal(t, 3*amountToSend, osmosisIBCBalance)

	// Test grantee still has exact amount expected
	gaiaGranteeIBCBalance, err := gaia.GetBalance(ctx, gaiaGranteeAddr, gaia.Config().Denom)
	require.NoError(t, err)
	require.Equal(t, granteeFundAmount, gaiaGranteeIBCBalance)

	// Test granter has less than they started with, meaning fees came from their account
	gaiaGranterIBCBalance, err := gaia.GetBalance(ctx, gaiaGranterAddr, gaia.Config().Denom)
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
