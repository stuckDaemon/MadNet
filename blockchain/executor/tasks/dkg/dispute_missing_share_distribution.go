package dkg

import (
	"context"
	"math/big"

	"github.com/MadBase/MadNet/blockchain/ethereum"
	"github.com/MadBase/MadNet/blockchain/executor/constants"
	"github.com/MadBase/MadNet/blockchain/executor/interfaces"
	"github.com/MadBase/MadNet/blockchain/executor/objects"
	"github.com/MadBase/MadNet/blockchain/executor/tasks/dkg/state"
	dkgUtils "github.com/MadBase/MadNet/blockchain/executor/tasks/dkg/utils"
	exUtils "github.com/MadBase/MadNet/blockchain/executor/tasks/utils"
	"github.com/MadBase/MadNet/blockchain/transaction"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

// DisputeMissingShareDistributionTask stores the data required to dispute shares
type DisputeMissingShareDistributionTask struct {
	*objects.Task
}

// asserting that DisputeMissingShareDistributionTask struct implements interface interfaces.Task
var _ interfaces.ITask = &DisputeMissingShareDistributionTask{}

// NewDisputeMissingShareDistributionTask creates a new task
func NewDisputeMissingShareDistributionTask(dkgState *state.DkgState, start uint64, end uint64) *DisputeMissingShareDistributionTask {
	return &DisputeMissingShareDistributionTask{
		Task: objects.NewTask(dkgState, constants.DisputeMissingShareDistributionTaskName, start, end),
	}
}

// Initialize begins the setup phase for DisputeMissingShareDistributionTask.
func (t *DisputeMissingShareDistributionTask) Initialize(ctx context.Context, logger *logrus.Entry, eth ethereum.Network) error {
	logger.Info("DisputeMissingShareDistributionTask Initializing...")
	return nil
}

// DoWork is the first attempt at disputing distributed shares
func (t *DisputeMissingShareDistributionTask) DoWork(ctx context.Context, logger *logrus.Entry, eth ethereum.Network) error {
	return t.doTask(ctx, logger, eth)
}

// DoRetry is subsequent attempts at disputing distributed shares
func (t *DisputeMissingShareDistributionTask) DoRetry(ctx context.Context, logger *logrus.Entry, eth ethereum.Network) error {
	return t.doTask(ctx, logger, eth)
}

func (t *DisputeMissingShareDistributionTask) doTask(ctx context.Context, logger *logrus.Entry, eth ethereum.Network) error {
	t.State.Lock()
	defer t.State.Unlock()

	taskState, ok := t.State.(*state.DkgState)
	if !ok {
		return objects.ErrCanNotContinue
	}

	logger.Info("DisputeMissingShareDistributionTask doTask()")

	accusableParticipants, err := t.getAccusableParticipants(ctx, eth, logger)
	if err != nil {
		return dkgUtils.LogReturnErrorf(logger, "DisputeMissingShareDistributionTask doTask() error getting accusableParticipants: %v", err)
	}

	// accuse missing validators
	if len(accusableParticipants) > 0 {
		logger.Warnf("Accusing missing distributed shares: %v", accusableParticipants)

		txnOpts, err := eth.GetTransactionOpts(ctx, taskState.Account)
		if err != nil {
			return dkgUtils.LogReturnErrorf(logger, "DisputeMissingShareDistributionTask doTask() error getting txnOpts: %v", err)
		}

		// If the TxOpts exists, meaning the Tx replacement timeout was reached,
		// we increase the Gas to have priority for the next blocks
		if t.TxOpts != nil && t.TxOpts.Nonce != nil {
			logger.Info("txnOpts Replaced")
			txnOpts.Nonce = t.TxOpts.Nonce
			txnOpts.GasFeeCap = t.TxOpts.GasFeeCap
			txnOpts.GasTipCap = t.TxOpts.GasTipCap
		}

		txn, err := eth.Contracts().Ethdkg().AccuseParticipantDidNotDistributeShares(txnOpts, accusableParticipants)
		if err != nil {
			return dkgUtils.LogReturnErrorf(logger, "DisputeMissingShareDistributionTask doTask() error accusing missing key shares: %v", err)
		}
		t.TxOpts.TxHashes = append(t.TxOpts.TxHashes, txn.Hash())
		t.TxOpts.GasFeeCap = txn.GasFeeCap()
		t.TxOpts.GasTipCap = txn.GasTipCap()
		t.TxOpts.Nonce = big.NewInt(int64(txn.Nonce()))

		logger.WithFields(logrus.Fields{
			"GasFeeCap": t.TxOpts.GasFeeCap,
			"GasTipCap": t.TxOpts.GasTipCap,
			"Nonce":     t.TxOpts.Nonce,
		}).Info("missing share dispute fees")

		// Queue transaction
		watcher := transaction.WatcherFromNetwork(eth)
		watcher.Subscribe(ctx, txn)
	} else {
		logger.Info("No accusations for missing distributed shares")
	}

	t.Success = true
	return nil
}

// ShouldRetry checks if it makes sense to try again
// if the DKG process is in the right phase and blocks
// range and there still someone to accuse, the retry
// is executed
func (t *DisputeMissingShareDistributionTask) ShouldRetry(ctx context.Context, logger *logrus.Entry, eth ethereum.Network) bool {

	t.State.Lock()
	defer t.State.Unlock()

	logger.Info("DisputeMissingShareDistributionTask ShouldRetry()")

	generalRetry := exUtils.GeneralTaskShouldRetry(ctx, logger, eth, t.Start, t.End)
	if !generalRetry {
		return false
	}

	taskState, ok := t.State.(*state.DkgState)
	if !ok {
		logger.Error("Invalid convertion of taskState object")
		return false
	}

	if taskState.Phase != state.ShareDistribution {
		return false
	}

	accusableParticipants, err := t.getAccusableParticipants(ctx, eth, logger)
	if err != nil {
		logger.Errorf("DisputeMissingShareDistributionTask ShouldRetry() error getting accusable participants: %v", err)
		return true
	}

	if len(accusableParticipants) > 0 {
		return true
	}

	return false
}

// DoDone creates a log entry saying task is complete
func (t *DisputeMissingShareDistributionTask) DoDone(logger *logrus.Entry) {
	t.State.Lock()
	defer t.State.Unlock()

	logger.WithField("Success", t.Success).Info("DisputeMissingShareDistributionTask done")
}

func (t *DisputeMissingShareDistributionTask) GetExecutionData() interfaces.ITaskExecutionData {
	return t.Task
}

func (t *DisputeMissingShareDistributionTask) getAccusableParticipants(ctx context.Context, eth ethereum.Network, logger *logrus.Entry) ([]common.Address, error) {

	taskState, ok := t.State.(*state.DkgState)
	if !ok {
		return nil, objects.ErrCanNotContinue
	}

	var accusableParticipants []common.Address
	callOpts, err := eth.GetCallOpts(ctx, taskState.Account)
	if err != nil {
		return nil, dkgUtils.LogReturnErrorf(logger, "DisputeMissingShareDistributionTask failed getting call options: %v", err)
	}

	validators, err := dkgUtils.GetValidatorAddressesFromPool(callOpts, eth, logger)
	if err != nil {
		return nil, dkgUtils.LogReturnErrorf(logger, "DisputeMissingShareDistributionTask getAccusableParticipants() error getting validators: %v", err)
	}

	validatorsMap := make(map[common.Address]bool)
	for _, validator := range validators {
		validatorsMap[validator] = true
	}

	// find participants who did not submit their shares
	var emptySharesHash [32]byte
	for _, p := range taskState.Participants {
		_, isValidator := validatorsMap[p.Address]
		if isValidator && (p.Nonce != taskState.Nonce ||
			p.Phase != state.ShareDistribution ||
			p.DistributedSharesHash == emptySharesHash) {
			// did not distribute shares
			accusableParticipants = append(accusableParticipants, p.Address)
		}
	}

	return accusableParticipants, nil
}