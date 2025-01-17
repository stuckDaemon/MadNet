package dkgtasks_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/MadBase/MadNet/blockchain/dkg/dkgevents"
	"github.com/MadBase/MadNet/blockchain/dkg/dkgtasks"
	"github.com/MadBase/MadNet/blockchain/dkg/dtest"
	"github.com/MadBase/MadNet/blockchain/objects"
	"github.com/MadBase/MadNet/crypto/bn256"
	"github.com/MadBase/MadNet/crypto/bn256/cloudflare"
	"github.com/MadBase/MadNet/logging"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// We test to ensure that everything behaves correctly.
func TestGPKjDisputeGoodAllValid(t *testing.T) {
	n := 4
	dkgStates, ecdsaPrivateKeys := dtest.InitializeNewDetDkgStateInfo(n)

	eth := connectSimulatorEndpoint(t, ecdsaPrivateKeys, 333*time.Millisecond)
	assert.NotNil(t, eth)
	defer eth.Close()

	ctx := context.Background()

	accounts := eth.GetKnownAccounts()

	owner := accounts[0]
	err := eth.UnlockAccount(owner)
	assert.Nil(t, err)

	// Start EthDKG
	ownerOpts, err := eth.GetTransactionOpts(ctx, owner)
	assert.Nil(t, err)

	// Check Stake
	callOpts := eth.GetCallOpts(ctx, owner)
	for _, acct := range accounts {
		stakeBalance, err := eth.Contracts().Staking().BalanceStakeFor(callOpts, acct.Address)
		assert.Nil(t, err)

		t.Logf("stakeBalance:%v", stakeBalance.String())
	}

	// Shorten ethdkg phase for testing purposes
	txn, err := eth.Contracts().Ethdkg().UpdatePhaseLength(ownerOpts, big.NewInt(100))
	assert.Nil(t, err)
	rcpt, err := eth.Queue().QueueAndWait(ctx, txn)
	assert.Nil(t, err)

	txn, err = eth.Contracts().Ethdkg().InitializeState(ownerOpts)
	assert.Nil(t, err)

	eth.Commit()
	rcpt, err = eth.Queue().QueueAndWait(ctx, txn)
	assert.Nil(t, err)

	for _, log := range rcpt.Logs {
		if log.Topics[0].String() == "0x9c6f8368fe7e77e8cb9438744581403bcb3f53298e517f04c1b8475487402e97" {
			event, err := eth.Contracts().Ethdkg().ParseRegistrationOpen(*log)
			assert.Nil(t, err)

			for _, dkgState := range dkgStates {
				dkgevents.PopulateSchedule(dkgState, event)
			}
		}
	}

	// Do Register task
	registerTasks := make([]*dkgtasks.RegisterTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		registerTasks[idx] = dkgtasks.NewRegisterTask(state)
		err = registerTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = registerTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, registerTasks[idx].Success)

		// Set Registration success to true
		dkgStates[idx].Registration = true
	}

	// Advance to share distribution phase
	advanceTo(t, eth, dkgStates[0].ShareDistributionStart)

	// Check public keys are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().PublicKeys(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().PublicKeys(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check points
		publicKey := dkgStates[idx].TransportPublicKey
		if (publicKey[0].Cmp(k0) != 0) || (publicKey[1].Cmp(k1) != 0) {
			t.Fatal("Invalid public key")
		}
	}

	// Do Share Distribution task
	shareDistributionTasks := make([]*dkgtasks.ShareDistributionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		shareDistributionTasks[idx] = dkgtasks.NewShareDistributionTask(state)
		err = shareDistributionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = shareDistributionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, shareDistributionTasks[idx].Success)

		// Set ShareDistribution success to true
		dkgStates[idx].ShareDistribution = true
	}
	// Ensure all participants have valid share information
	dtest.PopulateEncryptedSharesAndCommitments(dkgStates)

	// Advance to share dispute phase
	advanceTo(t, eth, dkgStates[0].DisputeStart)

	// Do Dispute task
	disputeTasks := make([]*dkgtasks.DisputeTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		disputeTasks[idx] = dkgtasks.NewDisputeTask(state)
		err = disputeTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = disputeTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, disputeTasks[idx].Success)

		// Set Dispute success to true
		dkgStates[idx].Dispute = true
	}

	// Confirm number of BadShares is zero
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		if len(state.BadShares) != 0 {
			t.Fatalf("Idx %v has incorrect number of BadShares", idx)
		}
	}

	// Advance to key share distribution phase
	advanceTo(t, eth, dkgStates[0].KeyShareSubmissionStart)
	dtest.GenerateKeyShares(dkgStates)

	// Do Key Share Submission task
	keyShareSubmissionTasks := make([]*dkgtasks.KeyshareSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		keyShareSubmissionTasks[idx] = dkgtasks.NewKeyshareSubmissionTask(state)
		err = keyShareSubmissionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = keyShareSubmissionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, keyShareSubmissionTasks[idx].Success)

		// Set KeyShareSubmission success to true
		dkgStates[idx].KeyShareSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err := eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Check key shares are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().KeyShares(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().KeyShares(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check points
		keyShareG1 := dkgStates[idx].KeyShareG1s[acct.Address]
		if (keyShareG1[0].Cmp(k0) != 0) || (keyShareG1[1].Cmp(k1) != 0) {
			t.Fatal("Invalid key share")
		}
	}

	// Advance to mpk submission phase
	advanceTo(t, eth, dkgStates[0].MPKSubmissionStart)
	dtest.GenerateMasterPublicKey(dkgStates)

	// Do MPK Submission task
	mpkSubmissionTasks := make([]*dkgtasks.MPKSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		mpkSubmissionTasks[idx] = dkgtasks.NewMPKSubmissionTask(state)
		err = mpkSubmissionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = mpkSubmissionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, mpkSubmissionTasks[idx].Success)

		// Set MPK submission success to true
		dkgStates[idx].MPKSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Validate MPK
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big1)
		assert.Nil(t, err)
		k2, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big2)
		assert.Nil(t, err)
		k3, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big3)
		assert.Nil(t, err)

		// check mpk
		mpk := dkgStates[idx].MasterPublicKey
		if (mpk[0].Cmp(k0) != 0) || (mpk[1].Cmp(k1) != 0) || (mpk[2].Cmp(k2) != 0) || (mpk[3].Cmp(k3) != 0) {
			t.Fatal("Invalid master public key")
		}
	}

	// Advance to gpkj submission phase
	advanceTo(t, eth, dkgStates[0].GPKJSubmissionStart)
	dtest.GenerateGPKJ(dkgStates)

	// Do MPK Submission task
	gpkjSubmitTasks := make([]*dkgtasks.GPKSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		adminHandler := new(adminHandlerMock)
		gpkjSubmitTasks[idx] = dkgtasks.NewGPKSubmissionTask(state, adminHandler)
		err = gpkjSubmitTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = gpkjSubmitTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, gpkjSubmitTasks[idx].Success)

		// Set GpkjSubmission success to true
		dkgStates[idx].GPKJSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Check gpkjs and signatures are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		s0, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		s1, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check signature
		signature := dkgStates[idx].GroupSignature
		if (signature[0].Cmp(s0) != 0) || (signature[1].Cmp(s1) != 0) {
			t.Fatal("Invalid signature")
		}

		k0, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)
		k2, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big2)
		assert.Nil(t, err)
		k3, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big3)
		assert.Nil(t, err)

		// check gpkj
		gpkj := dkgStates[idx].GroupPublicKey
		if (gpkj[0].Cmp(k0) != 0) || (gpkj[1].Cmp(k1) != 0) || (gpkj[2].Cmp(k2) != 0) || (gpkj[3].Cmp(k3) != 0) {
			t.Fatal("Invalid gpkj")
		}
	}

	// Advance to gpkj dispute phase
	advanceTo(t, eth, dkgStates[0].GPKJGroupAccusationStart)

	// Do GPKjDispute task
	tasks := make([]*dkgtasks.GPKJDisputeTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		tasks[idx] = dkgtasks.NewGPKJDisputeTask(state)
		logger.Errorf("Idx: %v\n", idx)
		err = tasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = tasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, tasks[idx].Success)

		// Set GPKjDispute success to true
		dkgStates[idx].GPKJGroupAccusation = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}
}

// We test to ensure that everything behaves correctly.
// Here, we have a malicious gpkj submission.
func TestGPKjDisputeGoodMaliciousGpkj(t *testing.T) {
	n := 4
	dkgStates, ecdsaPrivateKeys := dtest.InitializeNewDetDkgStateInfo(n)

	eth := connectSimulatorEndpoint(t, ecdsaPrivateKeys, 333*time.Millisecond)
	assert.NotNil(t, eth)
	defer eth.Close()

	ctx := context.Background()

	accounts := eth.GetKnownAccounts()

	owner := accounts[0]
	err := eth.UnlockAccount(owner)
	assert.Nil(t, err)

	// Start EthDKG
	ownerOpts, err := eth.GetTransactionOpts(ctx, owner)
	assert.Nil(t, err)

	// Check Stake
	stakeBalances := make([]*big.Int, n)
	callOpts := eth.GetCallOpts(ctx, owner)
	for idx, acct := range accounts {
		stakeBalances[idx], err = eth.Contracts().Staking().BalanceStakeFor(callOpts, acct.Address)
		assert.Nil(t, err)

		t.Logf("stakeBalance:%v", stakeBalances[idx].String())
	}

	// Shorten ethdkg phase for testing purposes
	txn, err := eth.Contracts().Ethdkg().UpdatePhaseLength(ownerOpts, big.NewInt(100))
	assert.Nil(t, err)
	rcpt, err := eth.Queue().QueueAndWait(ctx, txn)
	assert.Nil(t, err)

	txn, err = eth.Contracts().Ethdkg().InitializeState(ownerOpts)
	assert.Nil(t, err)

	eth.Commit()
	rcpt, err = eth.Queue().QueueAndWait(ctx, txn)
	assert.Nil(t, err)

	for _, log := range rcpt.Logs {
		if log.Topics[0].String() == "0x9c6f8368fe7e77e8cb9438744581403bcb3f53298e517f04c1b8475487402e97" {
			event, err := eth.Contracts().Ethdkg().ParseRegistrationOpen(*log)
			assert.Nil(t, err)

			for _, dkgState := range dkgStates {
				dkgevents.PopulateSchedule(dkgState, event)
			}
		}
	}

	// Do Register task
	registerTasks := make([]*dkgtasks.RegisterTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		registerTasks[idx] = dkgtasks.NewRegisterTask(state)
		err = registerTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = registerTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, registerTasks[idx].Success)

		// Set Registration success to true
		dkgStates[idx].Registration = true
	}

	// Advance to share distribution phase
	advanceTo(t, eth, dkgStates[0].ShareDistributionStart)

	// Check public keys are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().PublicKeys(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().PublicKeys(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check points
		publicKey := dkgStates[idx].TransportPublicKey
		if (publicKey[0].Cmp(k0) != 0) || (publicKey[1].Cmp(k1) != 0) {
			t.Fatal("Invalid public key")
		}
	}

	// Do Share Distribution task
	shareDistributionTasks := make([]*dkgtasks.ShareDistributionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		shareDistributionTasks[idx] = dkgtasks.NewShareDistributionTask(state)
		err = shareDistributionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = shareDistributionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, shareDistributionTasks[idx].Success)

		// Set ShareDistribution success to true
		dkgStates[idx].ShareDistribution = true
	}
	// Ensure all participants have valid share information
	dtest.PopulateEncryptedSharesAndCommitments(dkgStates)

	// Advance to share dispute phase
	advanceTo(t, eth, dkgStates[0].DisputeStart)

	// Do Dispute task
	disputeTasks := make([]*dkgtasks.DisputeTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		disputeTasks[idx] = dkgtasks.NewDisputeTask(state)
		err = disputeTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = disputeTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, disputeTasks[idx].Success)

		// Set Dispute success to true
		dkgStates[idx].Dispute = true
	}

	// Confirm number of BadShares is zero
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		if len(state.BadShares) != 0 {
			t.Fatalf("Idx %v has incorrect number of BadShares", idx)
		}
	}

	// Advance to key share distribution phase
	advanceTo(t, eth, dkgStates[0].KeyShareSubmissionStart)
	dtest.GenerateKeyShares(dkgStates)

	// Do Key Share Submission task
	keyShareSubmissionTasks := make([]*dkgtasks.KeyshareSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		keyShareSubmissionTasks[idx] = dkgtasks.NewKeyshareSubmissionTask(state)
		err = keyShareSubmissionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = keyShareSubmissionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, keyShareSubmissionTasks[idx].Success)

		// Set KeyShare success to true
		dkgStates[idx].KeyShareSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err := eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Check key shares are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().KeyShares(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().KeyShares(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check points
		keyShareG1 := dkgStates[idx].KeyShareG1s[acct.Address]
		if (keyShareG1[0].Cmp(k0) != 0) || (keyShareG1[1].Cmp(k1) != 0) {
			t.Fatal("Invalid key share")
		}
	}

	// Advance to mpk submission phase
	advanceTo(t, eth, dkgStates[0].MPKSubmissionStart)
	dtest.GenerateMasterPublicKey(dkgStates)

	// Do MPK Submission task
	mpkSubmissionTasks := make([]*dkgtasks.MPKSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		mpkSubmissionTasks[idx] = dkgtasks.NewMPKSubmissionTask(state)
		err = mpkSubmissionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = mpkSubmissionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, mpkSubmissionTasks[idx].Success)

		// Set MPK Submission success to true
		dkgStates[idx].MPKSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Validate MPK
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big1)
		assert.Nil(t, err)
		k2, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big2)
		assert.Nil(t, err)
		k3, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big3)
		assert.Nil(t, err)

		// check mpk
		mpk := dkgStates[idx].MasterPublicKey
		if (mpk[0].Cmp(k0) != 0) || (mpk[1].Cmp(k1) != 0) || (mpk[2].Cmp(k2) != 0) || (mpk[3].Cmp(k3) != 0) {
			t.Fatal("Invalid master public key")
		}
	}

	// Advance to gpkj submission phase
	advanceTo(t, eth, dkgStates[0].GPKJSubmissionStart)
	dtest.GenerateGPKJ(dkgStates)

	// Do GPKj Submission task
	badIdx := n - 1
	gpkjSubmitTasks := make([]*dkgtasks.GPKSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		adminHandler := new(adminHandlerMock)
		gpkjSubmitTasks[idx] = dkgtasks.NewGPKSubmissionTask(state, adminHandler)
		err = gpkjSubmitTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)

		if idx == badIdx {
			// Need to mess up information
			gskjBad := new(big.Int).Add(state.GroupPrivateKey, big.NewInt(1))
			// here's the group public
			gpkj := new(cloudflare.G2).ScalarBaseMult(gskjBad)
			gpkjBig, err := bn256.G2ToBigIntArray(gpkj)
			assert.Nil(t, err)
			// create sig
			sig, err := cloudflare.Sign(state.InitialMessage, gskjBad, cloudflare.HashToG1)
			assert.Nil(t, err)
			sigBig, err := bn256.G1ToBigIntArray(sig)
			assert.Nil(t, err)
			// verify signature
			validSig, err := cloudflare.Verify(state.InitialMessage, sig, gpkj, cloudflare.HashToG1)
			assert.Nil(t, err)
			assert.True(t, validSig)
			// Rewriting stuff
			state.GroupPrivateKey = gskjBad
			state.GroupPublicKey = gpkjBig
			state.GroupSignature = sigBig
		}

		err = gpkjSubmitTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, gpkjSubmitTasks[idx].Success)

		// Set GpkjSubmission success to true
		dkgStates[idx].GPKJSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Check gpkjs and signatures are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		s0, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		s1, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check signature
		signature := dkgStates[idx].GroupSignature
		if (signature[0].Cmp(s0) != 0) || (signature[1].Cmp(s1) != 0) {
			t.Fatal("Invalid signature")
		}

		k0, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)
		k2, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big2)
		assert.Nil(t, err)
		k3, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big3)
		assert.Nil(t, err)

		// check gpkj
		gpkj := dkgStates[idx].GroupPublicKey
		if (gpkj[0].Cmp(k0) != 0) || (gpkj[1].Cmp(k1) != 0) || (gpkj[2].Cmp(k2) != 0) || (gpkj[3].Cmp(k3) != 0) {
			t.Fatal("Invalid gpkj")
		}
	}

	// Advance to gpkj dispute phase
	advanceTo(t, eth, dkgStates[0].GPKJGroupAccusationStart)

	// Do GPKjDispute task
	tasks := make([]*dkgtasks.GPKJDisputeTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		tasks[idx] = dkgtasks.NewGPKJDisputeTask(state)
		err = tasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = tasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, tasks[idx].Success)

		// Set Dispute success to true
		dkgStates[idx].GPKJGroupAccusation = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	// Advance to Complete phase
	advanceTo(t, eth, dkgStates[0].CompleteStart)

	// Check gpkjs and signatures again
	for idx, acct := range accounts {
		if idx == badIdx {
			continue
		}
		callOpts := eth.GetCallOpts(context.Background(), acct)
		s0, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		s1, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check signature
		signature := dkgStates[idx].GroupSignature
		if (signature[0].Cmp(s0) != 0) || (signature[1].Cmp(s1) != 0) {
			t.Errorf("Invalid signature for idx = %v\n", idx)
			t.Logf("sig:  (%x,%x)\n", signature[0], signature[1])
			t.Logf("rcvd: (%x,%x)\n", s0, s1)
		}

		k0, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)
		k2, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big2)
		assert.Nil(t, err)
		k3, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big3)
		assert.Nil(t, err)

		// check gpkj
		gpkj := dkgStates[idx].GroupPublicKey
		if (gpkj[0].Cmp(k0) != 0) || (gpkj[1].Cmp(k1) != 0) || (gpkj[2].Cmp(k2) != 0) || (gpkj[3].Cmp(k3) != 0) {
			t.Errorf("Invalid gpkj for idx = %v\n", idx)
			t.Logf("gpkj: (%x,%x,%x,%x)\n", gpkj[0], gpkj[1], gpkj[2], gpkj[3])
			t.Logf("rcvd: (%x,%x,%x,%x)\n", k0, k1, k2, k3)
		}
	}

	// Do Complete task
	state0 := dkgStates[0]
	logger := logging.GetLogger("test").WithField("Validator", accounts[0].Address.String())
	completeTask := dkgtasks.NewCompletionTask(state0)
	err = completeTask.Initialize(ctx, logger, eth, state0)
	assert.Nil(t, err)
	err = completeTask.DoWork(ctx, logger, eth)
	assert.Nil(t, err)

	// Check Stake
	for idx, acct := range accounts {
		stakeBalance, err := eth.Contracts().Staking().BalanceStakeFor(callOpts, acct.Address)
		assert.Nil(t, err)
		assert.NotNil(t, stakeBalance)

		if idx == badIdx {
			assert.Equal(t, -1, stakeBalance.Cmp(stakeBalances[idx]))
		} else {
			assert.Equal(t, 0, stakeBalance.Cmp(stakeBalances[idx]))
		}
		t.Logf("New stake balance:%v", stakeBalance)
	}
}

// We test to ensure that everything behaves correctly.
// Here, we have a malicious accusation.
func TestGPKjDisputeGoodMaliciousAccusation(t *testing.T) {
	n := 4
	dkgStates, ecdsaPrivateKeys := dtest.InitializeNewDetDkgStateInfo(n)

	eth := connectSimulatorEndpoint(t, ecdsaPrivateKeys, 333*time.Millisecond)
	assert.NotNil(t, eth)
	defer eth.Close()

	ctx := context.Background()

	accounts := eth.GetKnownAccounts()

	owner := accounts[0]
	err := eth.UnlockAccount(owner)
	assert.Nil(t, err)

	// Start EthDKG
	ownerOpts, err := eth.GetTransactionOpts(ctx, owner)
	assert.Nil(t, err)

	// Check Stake
	stakeBalances := make([]*big.Int, n)
	callOpts := eth.GetCallOpts(ctx, owner)
	for idx, acct := range accounts {
		stakeBalances[idx], err = eth.Contracts().Staking().BalanceStakeFor(callOpts, acct.Address)
		assert.Nil(t, err)

		t.Logf("stakeBalance:%v", stakeBalances[idx].String())
	}

	// Shorten ethdkg phase for testing purposes
	txn, err := eth.Contracts().Ethdkg().UpdatePhaseLength(ownerOpts, big.NewInt(100))
	assert.Nil(t, err)
	rcpt, err := eth.Queue().QueueAndWait(ctx, txn)
	assert.Nil(t, err)

	txn, err = eth.Contracts().Ethdkg().InitializeState(ownerOpts)
	assert.Nil(t, err)

	eth.Commit()
	rcpt, err = eth.Queue().QueueAndWait(ctx, txn)
	assert.Nil(t, err)

	for _, log := range rcpt.Logs {
		if log.Topics[0].String() == "0x9c6f8368fe7e77e8cb9438744581403bcb3f53298e517f04c1b8475487402e97" {
			event, err := eth.Contracts().Ethdkg().ParseRegistrationOpen(*log)
			assert.Nil(t, err)

			for _, dkgState := range dkgStates {
				dkgevents.PopulateSchedule(dkgState, event)
			}
		}
	}

	// Do Register task
	registerTasks := make([]*dkgtasks.RegisterTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		registerTasks[idx] = dkgtasks.NewRegisterTask(state)
		err = registerTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = registerTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, registerTasks[idx].Success)

		// Set Registration success to true
		dkgStates[idx].Registration = true
	}

	// Advance to share distribution phase
	advanceTo(t, eth, dkgStates[0].ShareDistributionStart)

	// Check public keys are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().PublicKeys(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().PublicKeys(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check points
		publicKey := dkgStates[idx].TransportPublicKey
		if (publicKey[0].Cmp(k0) != 0) || (publicKey[1].Cmp(k1) != 0) {
			t.Fatal("Invalid public key")
		}
	}

	// Do Share Distribution task
	shareDistributionTasks := make([]*dkgtasks.ShareDistributionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		shareDistributionTasks[idx] = dkgtasks.NewShareDistributionTask(state)
		err = shareDistributionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = shareDistributionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, shareDistributionTasks[idx].Success)

		// Set ShareDistribution success to true
		dkgStates[idx].ShareDistribution = true
	}
	// Ensure all participants have valid share information
	dtest.PopulateEncryptedSharesAndCommitments(dkgStates)

	// Advance to share dispute phase
	advanceTo(t, eth, dkgStates[0].DisputeStart)

	// Do Dispute task
	disputeTasks := make([]*dkgtasks.DisputeTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		disputeTasks[idx] = dkgtasks.NewDisputeTask(state)
		err = disputeTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = disputeTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, disputeTasks[idx].Success)

		// Set Dispute success to true
		dkgStates[idx].Dispute = true
	}

	// Confirm number of BadShares is zero
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		if len(state.BadShares) != 0 {
			t.Fatalf("Idx %v has incorrect number of BadShares", idx)
		}
	}

	// Advance to key share distribution phase
	advanceTo(t, eth, dkgStates[0].KeyShareSubmissionStart)
	dtest.GenerateKeyShares(dkgStates)

	// Do Key Share Submission task
	keyShareSubmissionTasks := make([]*dkgtasks.KeyshareSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		keyShareSubmissionTasks[idx] = dkgtasks.NewKeyshareSubmissionTask(state)
		err = keyShareSubmissionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = keyShareSubmissionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, keyShareSubmissionTasks[idx].Success)

		// Set KeyShare success to true
		dkgStates[idx].KeyShareSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err := eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Check key shares are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().KeyShares(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().KeyShares(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check points
		keyShareG1 := dkgStates[idx].KeyShareG1s[acct.Address]
		if (keyShareG1[0].Cmp(k0) != 0) || (keyShareG1[1].Cmp(k1) != 0) {
			t.Fatal("Invalid key share")
		}
	}

	// Advance to mpk submission phase
	advanceTo(t, eth, dkgStates[0].MPKSubmissionStart)
	dtest.GenerateMasterPublicKey(dkgStates)

	// Do MPK Submission task
	mpkSubmissionTasks := make([]*dkgtasks.MPKSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		mpkSubmissionTasks[idx] = dkgtasks.NewMPKSubmissionTask(state)
		err = mpkSubmissionTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		err = mpkSubmissionTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, mpkSubmissionTasks[idx].Success)

		// Set MPKSubmission success to true
		dkgStates[idx].MPKSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Validate MPK
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		k0, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big1)
		assert.Nil(t, err)
		k2, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big2)
		assert.Nil(t, err)
		k3, err := eth.Contracts().Ethdkg().MasterPublicKey(callOpts, common.Big3)
		assert.Nil(t, err)

		// check mpk
		mpk := dkgStates[idx].MasterPublicKey
		if (mpk[0].Cmp(k0) != 0) || (mpk[1].Cmp(k1) != 0) || (mpk[2].Cmp(k2) != 0) || (mpk[3].Cmp(k3) != 0) {
			t.Fatal("Invalid master public key")
		}
	}

	// Advance to gpkj submission phase
	advanceTo(t, eth, dkgStates[0].GPKJSubmissionStart)
	dtest.GenerateGPKJ(dkgStates)

	// Do GPKj Submission task
	gpkjSubmitTasks := make([]*dkgtasks.GPKSubmissionTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		adminHandler := new(adminHandlerMock)
		gpkjSubmitTasks[idx] = dkgtasks.NewGPKSubmissionTask(state, adminHandler)
		err = gpkjSubmitTasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)

		err = gpkjSubmitTasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, gpkjSubmitTasks[idx].Success)

		// Set GpkjSubmission success to true
		dkgStates[idx].GPKJSubmission = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	eth.Commit()

	// Check gpkjs and signatures are present and valid
	for idx, acct := range accounts {
		callOpts := eth.GetCallOpts(context.Background(), acct)
		s0, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		s1, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check signature
		signature := dkgStates[idx].GroupSignature
		if (signature[0].Cmp(s0) != 0) || (signature[1].Cmp(s1) != 0) {
			t.Fatal("Invalid signature")
		}

		k0, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)
		k2, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big2)
		assert.Nil(t, err)
		k3, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big3)
		assert.Nil(t, err)

		// check gpkj
		gpkj := dkgStates[idx].GroupPublicKey
		if (gpkj[0].Cmp(k0) != 0) || (gpkj[1].Cmp(k1) != 0) || (gpkj[2].Cmp(k2) != 0) || (gpkj[3].Cmp(k3) != 0) {
			t.Fatal("Invalid gpkj")
		}
	}

	// Advance to gpkj dispute phase
	advanceTo(t, eth, dkgStates[0].GPKJGroupAccusationStart)

	// Do GPKjDispute task
	// Performs the malicious accusation
	badIdx := n - 1
	// Is maliciously accused
	goodIdx := n - 2
	tasks := make([]*dkgtasks.GPKJDisputeTask, n)
	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())

		tasks[idx] = dkgtasks.NewGPKJDisputeTask(state)
		err = tasks[idx].Initialize(ctx, logger, eth, state)
		assert.Nil(t, err)
		if idx == badIdx {
			state.DishonestValidators = objects.ParticipantList{state.Participants[goodIdx].Copy()}
		}
		err = tasks[idx].DoWork(ctx, logger, eth)
		assert.Nil(t, err)

		eth.Commit()
		assert.True(t, tasks[idx].Success)

		// Set GPKjDispute success to true
		dkgStates[idx].GPKJGroupAccusation = true
	}

	// Double check to Make sure all transactions were good
	rcpts, err = eth.Queue().WaitGroupTransactions(ctx, 1)
	assert.Nil(t, err)

	for _, rcpt := range rcpts {
		assert.NotNil(t, rcpt)
		assert.Equal(t, uint64(1), rcpt.Status)
	}

	// Advance to Complete phase
	advanceTo(t, eth, dkgStates[0].CompleteStart)

	// Check gpkjs and signatures again
	for idx, acct := range accounts {
		if idx == badIdx {
			continue
		}
		callOpts := eth.GetCallOpts(context.Background(), acct)
		s0, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		s1, err := eth.Contracts().Ethdkg().InitialSignatures(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)

		// check signature
		signature := dkgStates[idx].GroupSignature
		if (signature[0].Cmp(s0) != 0) || (signature[1].Cmp(s1) != 0) {
			t.Errorf("Invalid signature for idx = %v\n", idx)
			t.Logf("sig:  (%x,%x)\n", signature[0], signature[1])
			t.Logf("rcvd: (%x,%x)\n", s0, s1)
		}

		k0, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big0)
		assert.Nil(t, err)
		k1, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big1)
		assert.Nil(t, err)
		k2, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big2)
		assert.Nil(t, err)
		k3, err := eth.Contracts().Ethdkg().GpkjSubmissions(callOpts, acct.Address, common.Big3)
		assert.Nil(t, err)

		// check gpkj
		gpkj := dkgStates[idx].GroupPublicKey
		if (gpkj[0].Cmp(k0) != 0) || (gpkj[1].Cmp(k1) != 0) || (gpkj[2].Cmp(k2) != 0) || (gpkj[3].Cmp(k3) != 0) {
			t.Errorf("Invalid gpkj for idx = %v\n", idx)
			t.Logf("gpkj: (%x,%x,%x,%x)\n", gpkj[0], gpkj[1], gpkj[2], gpkj[3])
			t.Logf("rcvd: (%x,%x,%x,%x)\n", k0, k1, k2, k3)
		}
	}

	// Do Complete task
	state0 := dkgStates[0]
	logger := logging.GetLogger("test").WithField("Validator", accounts[0].Address.String())
	completeTask := dkgtasks.NewCompletionTask(state0)
	err = completeTask.Initialize(ctx, logger, eth, state0)
	assert.Nil(t, err)
	err = completeTask.DoWork(ctx, logger, eth)
	assert.Nil(t, err)

	// Check Stake
	for idx, acct := range accounts {
		stakeBalance, err := eth.Contracts().Staking().BalanceStakeFor(callOpts, acct.Address)
		assert.Nil(t, err)
		assert.NotNil(t, stakeBalance)

		if idx == badIdx {
			assert.Equal(t, -1, stakeBalance.Cmp(stakeBalances[idx]))
		} else {
			assert.Equal(t, 0, stakeBalance.Cmp(stakeBalances[idx]))
		}
		t.Logf("New stake balance:%v", stakeBalance)
	}
}

// We begin by submitting invalid information.
// This test is meant to raise an error resulting from an invalid argument
// for the Ethereum interface.
func TestGPKjDisputeBad1(t *testing.T) {
	n := 4
	_, ecdsaPrivateKeys := dtest.InitializeNewDetDkgStateInfo(n)
	logger := logging.GetLogger("ethereum")
	logger.SetLevel(logrus.DebugLevel)
	eth := connectSimulatorEndpoint(t, ecdsaPrivateKeys, 333*time.Millisecond)
	defer eth.Close()

	acct := eth.GetKnownAccounts()[0]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a task to share distribution and make sure it succeeds
	state := objects.NewDkgState(acct)
	task := dkgtasks.NewGPKJDisputeTask(state)
	log := logger.WithField("TaskID", "foo")

	defer func() {
		// If we didn't get here by recovering from a panic() we failed
		if reason := recover(); reason == nil {
			t.Log("No panic in sight")
			t.Fatal("Should have panicked")
		} else {
			t.Logf("Good panic because: %v", reason)
		}
	}()
	task.Initialize(ctx, log, eth, nil)
}

// We test to ensure that everything behaves correctly.
// This test is meant to raise an error resulting from
// not proceeding to GPKjDispute phase.
func TestGPKjDisputeBad2(t *testing.T) {
	n := 4
	_, ecdsaPrivateKeys := dtest.InitializeNewDetDkgStateInfo(n)
	logger := logging.GetLogger("ethereum")
	logger.SetLevel(logrus.DebugLevel)
	eth := connectSimulatorEndpoint(t, ecdsaPrivateKeys, 333*time.Millisecond)
	defer eth.Close()

	acct := eth.GetKnownAccounts()[0]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Do bad Share Dispute task
	state := objects.NewDkgState(acct)
	task := dkgtasks.NewGPKJDisputeTask(state)
	log := logger.WithField("TaskID", "foo")
	err := task.Initialize(ctx, log, eth, state)
	if err == nil {
		t.Fatal("Should have raised error")
	}
}
