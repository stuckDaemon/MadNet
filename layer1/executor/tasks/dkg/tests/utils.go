package dkg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"github.com/MadBase/MadNet/bridge/bindings"
	"github.com/MadBase/MadNet/crypto/bn256"
	"github.com/MadBase/MadNet/crypto/bn256/cloudflare"
	"github.com/MadBase/MadNet/layer1"
	"github.com/MadBase/MadNet/layer1/ethereum"
	"github.com/MadBase/MadNet/layer1/executor/tasks"
	"github.com/MadBase/MadNet/layer1/executor/tasks/dkg"
	"github.com/MadBase/MadNet/layer1/executor/tasks/dkg/state"
	"github.com/MadBase/MadNet/layer1/executor/tasks/dkg/tests/cmd"
	"github.com/MadBase/MadNet/layer1/executor/tasks/dkg/utils"
	"github.com/MadBase/MadNet/layer1/monitor/events"
	//"github.com/MadBase/MadNet/layer1/monitor/events"

	"github.com/MadBase/MadNet/layer1/transaction"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/MadBase/MadNet/logging"
)

func Init(workingDir string, n int) ([]string, error) {

	// Resources setup
	//err := cmd.RunSetup(workingDir)
	//if err != nil {
	//	return err
	//}
	validatorAddresses, err := cmd.RunInit(workingDir, n)
	if err != nil {
		return nil, err
	}

	return validatorAddresses, nil
}

func BuildTestEnvironment(t *testing.T, validatorsCount int) ([]string, error) {

	workingDir := cmd.CreateTestWorkingFolder()

	err := cmd.RunSetup(workingDir)
	assert.Nil(t, err)

	validatorAddresses, err := cmd.RunInit(workingDir, validatorsCount)
	assert.Nil(t, err)

	return validatorAddresses, nil
}

func GetEthereumNetwork(t *testing.T, cleanStart bool, workingDir string) layer1.Client {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	isRunning, _ := cmd.IsHardHatRunning()
	if !isRunning {
		log.Printf("Hardhat is not running. Start new HardHat")
		startHardHat(t, ctx)
	}

	if cleanStart {
		err := cmd.StopHardHat()
		assert.Nilf(t, err, "Failed to stopHardHat")
		startHardHat(t, ctx)
	}

	eth, err := ethereum.NewClient(
		"http://localhost:8545",
		filepath.Join(workingDir, "keystores", "keys"),
		filepath.Join(workingDir, "keystores"),
		"",
		0,
		500,
		1)
	assert.Nil(t, err, "Failed to build Ethereum endpoint...")

	log.Printf("Deploying contracts ...")
	_, err = cmd.RunDeploy(workingDir)

	// Unlock the default account and use it to deploy contracts
	defaultAccount := eth.GetDefaultAccount()
	err = eth.UnlockAccount(defaultAccount)
	assert.Nil(t, err, "Failed to unlock default account")

	t.Logf("Default account: %v", defaultAccount.Address.String())
	t.Logf("deploying contracts..")

	// unlock accounts
	for _, account := range eth.GetKnownAccounts() {
		err := eth.UnlockAccount(account)
		assert.Nil(t, err)
	}

	// fund accounts
	for _, account := range eth.GetKnownAccounts()[1:] {
		txn, err := ethereum.TransferEther(eth, nil, defaultAccount.Address, account.Address, big.NewInt(100000000000000000))
		assert.Nil(t, err)
		assert.NotNil(t, txn)
		if txn == nil {
			// this shouldn't be needed, but is
			eth.Close()
			t.Fatal("could not transfer ether")
		}
		//watcher := transaction.NewWatcher(eth, transaction.NewKnownSelectors(), eth.GetFinalityDelay())
		//watcher.StartLoop()
		//
		//rcpt, err := watcher.SubscribeAndWait(ctx, txn)
		//assert.Nil(t, err)
		//assert.NotNil(t, rcpt)
	}

	return eth
}

// SetupPrivateKeys computes deterministic private keys for testing
func SetupPrivateKeys(n int) []*ecdsa.PrivateKey {
	if (n < 1) || (n >= 256) {
		panic("invalid number for accounts")
	}
	secp256k1N, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	baseBytes := make([]byte, 32)
	baseBytes[0] = 255
	baseBytes[31] = 255
	privKeyArray := []*ecdsa.PrivateKey{}
	for k := 0; k < n; k++ {
		privKeyBytes := CopySlice(baseBytes)
		privKeyBytes[1] = uint8(k)
		privKeyBig := new(big.Int).SetBytes(privKeyBytes)
		privKeyBig.Mod(privKeyBig, secp256k1N)
		privKeyBytes = privKeyBig.Bytes()
		privKey, err := crypto.ToECDSA(privKeyBytes)
		if err != nil {
			panic(err)
		}
		privKeyArray = append(privKeyArray, privKey)
	}
	return privKeyArray
}

func CopySlice(v []byte) []byte {
	out := make([]byte, len(v))
	copy(out, v)
	return out
}

// SetupAccounts derives the associated addresses from private keys
func SetupAccounts(privKeys []*ecdsa.PrivateKey) []accounts.Account {
	accountsArray := []accounts.Account{}
	for _, pk := range privKeys {
		commonAddr := crypto.PubkeyToAddress(pk.PublicKey)
		accountValue := accounts.Account{Address: commonAddr}
		accountsArray = append(accountsArray, accountValue)
	}
	return accountsArray
}

func GetMadnetRootPath() []string {

	rootPath := []string{string(os.PathSeparator)}

	cmd := exec.Command("go", "list", "-m", "-f", "'{{.Dir}}'", "github.com/MadBase/MadNet")
	stdout, err := cmd.Output()
	if err != nil {
		log.Printf("Error getting project root path: %v", err)
		return rootPath
	}

	path := string(stdout)
	path = strings.ReplaceAll(path, "'", "")
	path = strings.ReplaceAll(path, "\n", "")

	pathNodes := strings.Split(path, string(os.PathSeparator))
	for _, pathNode := range pathNodes {
		rootPath = append(rootPath, pathNode)
	}

	return rootPath
}

func InitializePrivateKeysAndAccounts(n int) ([]*ecdsa.PrivateKey, []accounts.Account) {
	_, pKey, err := GetOwnerAccount()
	if err != nil {
		panic(err)
	}

	//t.Logf("owner: %v, pvKey: %v", account.Address.String(), key.PrivateKey)
	privateKeys := []*ecdsa.PrivateKey{pKey}
	randomPrivateKeys := SetupPrivateKeys(n - 1)
	privateKeys = append(privateKeys, randomPrivateKeys...)
	accounts := SetupAccounts(privateKeys)

	return privateKeys, accounts
}

func ReadFromFileOnRoot(filePath string, configVar string) (string, error) {
	rootPath := GetMadnetRootPath()
	rootPath = append(rootPath, filePath)
	fileFullPath := filepath.Join(rootPath...)

	f, err := os.Open(fileFullPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Splits on newlines by default.
	scanner := bufio.NewScanner(f)
	var defaultAccount string

	// https://golang.org/pkg/bufio/#Scanner.Scan
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), configVar) {
			defaultAccount = scanner.Text()
			break
		}
	}

	splits := strings.Split(defaultAccount, "=")
	return strings.Trim(splits[1], " \""), nil
}

func GetOwnerAccount() (*common.Address, *ecdsa.PrivateKey, error) {
	rootPath := GetMadnetRootPath()

	// open config file owner.toml
	acctAddress, err := ReadFromFileOnRoot("scripts/base-files/owner.toml", "defaultAccount")
	if err != nil {
		return nil, nil, err
	}
	acctAddressLowerCase := strings.ToLower(acctAddress)

	// open password file
	passwordPath := append(rootPath, "scripts")
	passwordPath = append(passwordPath, "base-files")
	passwordPath = append(passwordPath, "passwordFile")
	passwordFullPath := filepath.Join(passwordPath...)

	fileContent, err := ioutil.ReadFile(passwordFullPath)
	if err != nil {
		//log.Errorf("error opening passsword file: %v", err)
		panic(err)
	}

	// Convert []byte to string
	password := string(fileContent)

	// open wallet json file
	walletPath := append(rootPath, "scripts")
	walletPath = append(walletPath, "base-files")
	walletPath = append(walletPath, acctAddressLowerCase)
	walletFullPath := filepath.Join(walletPath...)

	jsonBytes, err := ioutil.ReadFile(walletFullPath)
	if err != nil {
		panic(err)
	}

	key, err := keystore.DecryptKey(jsonBytes, password)
	if err != nil {
		panic(err)
	}

	return &key.Address, key.PrivateKey, nil
}

func startHardHat(t *testing.T, ctx context.Context) *ethereum.Client {

	log.Printf("Starting HardHat ...")
	err := cmd.RunHardHatNode()
	assert.Nilf(t, err, "Error starting hardhat node")

	err = cmd.WaitForHardHatNode(ctx)
	assert.Nilf(t, err, "Failed to wait for hardhat to be up and running")

	return nil
}

// setCommandStdOut If ENABLE_SCRIPT_LOG env variable is set as 'true' the command will show scripts logs
func setCommandStdOut(cmd *exec.Cmd) {

	flagValue, found := os.LookupEnv("ENABLE_SCRIPT_LOG")
	enabled, err := strconv.ParseBool(flagValue)

	if err == nil && found && enabled {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	}
}

// SendHardhatCommand sends a command to the hardhat server via an RPC call
func SendHardhatCommand(command string, params ...interface{}) error {

	commandJson := &ethereum.JsonRPCMessage{
		Version: "2.0",
		ID:      []byte("1"),
		Method:  command,
		Params:  make([]byte, 0),
	}

	paramsJson, err := json.Marshal(params)
	if err != nil {
		return err
	}

	commandJson.Params = paramsJson

	c := http.Client{}
	var buff bytes.Buffer
	err = json.NewEncoder(&buff).Encode(commandJson)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(buff.Bytes())

	resp, err := c.Post(
		"http://127.0.0.1:8545",
		"application/json",
		reader,
	)

	if err != nil {
		return err
	}

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return nil
}

// MineBlocks mines a certain number of hardhat blocks
func MineBlocks(t *testing.T, eth layer1.Client, blocksToMine uint64) {
	var blocksToMineString = "0x" + strconv.FormatUint(blocksToMine, 16)
	log.Printf("hardhat_mine %v blocks ", blocksToMine)
	err := SendHardhatCommand("hardhat_mine", blocksToMineString)
	if err != nil {
		panic(err)
	}
}

// AdvanceTo advance to a certain block number
func AdvanceTo(t *testing.T, eth layer1.Client, target uint64) {
	currentBlock, err := eth.GetCurrentHeight(context.Background())
	if err != nil {
		panic(err)
	}
	if target < currentBlock {
		return
	}
	blocksToMine := target - currentBlock
	var blocksToMineString = "0x" + strconv.FormatUint(blocksToMine, 16)

	log.Printf("hardhat_mine %v blocks to target height %v", blocksToMine, target)

	err = SendHardhatCommand("hardhat_mine", blocksToMineString)
	if err != nil {
		panic(err)
	}
}

// SetNextBlockBaseFee The the Base fee for the next hardhat block. Can be used to make tx stale.
func SetNextBlockBaseFee(t *testing.T, eth layer1.Client, target uint64) {
	log.Printf("Setting hardhat_setNextBlockBaseFeePerGas to %v", target)

	err := SendHardhatCommand("hardhat_setNextBlockBaseFeePerGas", "0x"+strconv.FormatUint(target, 16))
	if err != nil {
		panic(err)
	}
}

// SetAutoMine Enable/disable hardhat autoMine
func SetAutoMine(t *testing.T, eth layer1.Client, autoMine bool) {
	log.Printf("Setting Automine to %v", autoMine)

	err := SendHardhatCommand("evm_setAutomine", autoMine)
	if err != nil {
		panic(err)
	}
}

// SetBlockInterval Set the interval between hardhat blocks. In case interval is 0, we enter in
// manual mode and blocks can only be mined explicitly by calling `MineBlocks`.
// This function disables autoMine.
func SetBlockInterval(t *testing.T, eth layer1.Client, intervalInMilliSeconds uint64) {
	SetAutoMine(t, eth, false)
	log.Printf("Setting block interval to %v seconds", intervalInMilliSeconds)
	err := SendHardhatCommand("evm_setIntervalMining", intervalInMilliSeconds)
	if err != nil {
		panic(err)
	}
}

type TestSuite struct {
	Eth              layer1.Client
	DKGStates        []*state.DkgState
	ecdsaPrivateKeys []*ecdsa.PrivateKey

	regTasks                     []*dkg.RegisterTask
	DispMissingRegTasks          []*dkg.DisputeMissingRegistrationTask
	ShareDistTasks               []*dkg.ShareDistributionTask
	DisputeMissingShareDistTasks []*dkg.DisputeMissingShareDistributionTask
	DisputeShareDistTasks        []*dkg.DisputeShareDistributionTask
	KeyshareSubmissionTasks      []*dkg.KeyShareSubmissionTask
	DisputeMissingKeyshareTasks  []*dkg.DisputeMissingKeySharesTask
	MpkSubmissionTasks           []*dkg.MPKSubmissionTask
	GpkjSubmissionTasks          []*dkg.GPKjSubmissionTask
	DisputeMissingGPKjTasks      []*dkg.DisputeMissingGPKjTask
	DisputeGPKjTasks             []*dkg.DisputeGPKjTask
	CompletionTasks              []*dkg.CompletionTask
}

func SetETHDKGPhaseLength(length uint16, eth layer1.Client, callOpts *bind.TransactOpts, ctx context.Context) (*types.Transaction, *types.Receipt, error) {
	// Shorten ethdkg phase for testing purposes
	ethdkgABI, err := abi.JSON(strings.NewReader(bindings.ETHDKGMetaData.ABI))
	if err != nil {
		return nil, nil, err
	}

	input, err := ethdkgABI.Pack("setPhaseLength", uint16(length))
	if err != nil {
		return nil, nil, err
	}

	txn, err := ethereum.GetContracts().ContractFactory().CallAny(callOpts, ethereum.GetContracts().EthdkgAddress(), big.NewInt(0), input)
	if err != nil {
		return nil, nil, err
	}
	if txn == nil {
		return nil, nil, errors.New("non existent transaction ContractFactory.CallAny(ethdkg, setPhaseLength(...))")
	}

	watcher := transaction.WatcherFromNetwork(eth, nil, true)
	rcpt, err := watcher.SubscribeAndWait(ctx, txn, nil)
	if err != nil {
		return nil, nil, err
	}
	if rcpt == nil {
		return nil, nil, errors.New("non existent receipt for tx ContractFactory.CallAny(ethdkg, setPhaseLength(...))")
	}

	return txn, rcpt, nil
}

func InitializeETHDKG(eth layer1.Client, callOpts *bind.TransactOpts, ctx context.Context) (*types.Transaction, *types.Receipt, error) {
	// Shorten ethdkg phase for testing purposes
	validatorPoolABI, err := abi.JSON(strings.NewReader(bindings.ValidatorPoolMetaData.ABI))
	if err != nil {
		return nil, nil, err
	}

	input, err := validatorPoolABI.Pack("initializeETHDKG")
	if err != nil {
		return nil, nil, err
	}

	txn, err := ethereum.GetContracts().ContractFactory().CallAny(callOpts, ethereum.GetContracts().ValidatorPoolAddress(), big.NewInt(0), input)
	if err != nil {
		return nil, nil, err
	}
	if txn == nil {
		return nil, nil, errors.New("non existent transaction ContractFactory.CallAny(validatorPool, initializeETHDKG())")
	}

	watcher := transaction.WatcherFromNetwork(eth, nil, false)
	rcpt, err := watcher.SubscribeAndWait(ctx, txn, nil)
	if err != nil {
		return nil, nil, err
	}
	if rcpt == nil {
		return nil, nil, errors.New("non existent receipt for tx ContractFactory.CallAny(validatorPool, initializeETHDKG())")
	}

	return txn, rcpt, nil
}

func StartFromRegistrationOpenPhase(t *testing.T, n int, unregisteredValidators int, phaseLength uint16) *TestSuite {
	ecdsaPrivateKeys, accounts := InitializePrivateKeysAndAccounts(n)

	eth := GetEthereumNetwork(t, false, "")
	assert.NotNil(t, eth)

	ctx := context.Background()
	owner := accounts[0]

	// Start EthDKG
	ownerOpts, err := eth.GetTransactionOpts(ctx, owner)
	assert.Nil(t, err)

	// Shorten ethdkg phase for testing purposes
	_, _, err = SetETHDKGPhaseLength(phaseLength, eth, ownerOpts, ctx)
	assert.Nil(t, err)

	// init ETHDKG on ValidatorPool, through ContractFactory
	_, rcpt, err := InitializeETHDKG(eth, ownerOpts, ctx)
	assert.Nil(t, err)

	event, err := tasks.GetETHDKGRegistrationOpened(rcpt.Logs, eth)
	assert.Nil(t, err)
	assert.NotNil(t, event)

	logger := logging.GetLogger("test").WithField("action", "GetValidatorAddressesFromPool")
	callOpts, err := eth.GetCallOpts(ctx, eth.GetDefaultAccount())
	assert.Nil(t, err)
	validatorAddresses, err := utils.GetValidatorAddresses(nil, logger)
	assert.Nil(t, err)

	phase, err := ethereum.GetContracts().Ethdkg().GetETHDKGPhase(callOpts)
	assert.Nil(t, err)
	assert.Equal(t, uint8(state.RegistrationOpen), phase)

	valCount, err := ethereum.GetContracts().ValidatorPool().GetValidatorsCount(callOpts)
	assert.Nil(t, err)
	assert.Equal(t, uint64(n), valCount.Uint64())

	// Do Register task
	regTasks := make([]*dkg.RegisterTask, n)
	dispMissingRegTasks := make([]*dkg.DisputeMissingRegistrationTask, n)
	dkgStates := make([]*state.DkgState, n)
	for idx := 0; idx < n; idx++ {
		//logger := logging.GetLogger("test").WithField("Validator", accounts[idx].Address.String())
		// Set Registration success to true
		state, regTask, dispMissingRegTask := events.UpdateStateOnRegistrationOpened(
			accounts[idx],
			event.StartBlock.Uint64(),
			event.PhaseLength.Uint64(),
			event.ConfirmationLength.Uint64(),
			event.Nonce.Uint64(),
			true,
			validatorAddresses,
		)

		dkgStates[idx] = state
		regTasks[idx] = regTask
		dispMissingRegTasks[idx] = dispMissingRegTask

		//err = regTasks[idx].Initialize(ctx, logger, eth)
		//assert.Nil(t, err)

		if idx >= n-unregisteredValidators {
			continue
		}

		nVal, err := ethereum.GetContracts().Ethdkg().GetNumParticipants(callOpts)
		assert.Nil(t, err)
		assert.Equal(t, uint64(idx), nVal.Uint64())

		//err = regTasks[idx].DoWork(ctx, logger, eth)
		//assert.Nil(t, err)
		//
		//assert.True(t, regTasks[idx].Success)
	}

	// simulate receiving AddressRegistered event
	for i := 0; i < n; i++ {
		state := dkgStates[i]

		if i >= n-unregisteredValidators {
			continue
		}

		for j := 0; j < n; j++ {
			dkgStates[j].OnAddressRegistered(state.Account.Address, i+1, state.Nonce, state.TransportPublicKey)
		}
	}

	shareDistributionTasks := make([]*dkg.ShareDistributionTask, n)
	disputeMissingShareDistributionTasks := make([]*dkg.DisputeMissingShareDistributionTask, n)
	disputeShareDistTasks := make([]*dkg.DisputeShareDistributionTask, n)

	if unregisteredValidators == 0 {
		height, err := eth.GetCurrentHeight(ctx)
		assert.Nil(t, err)

		for idx := 0; idx < n; idx++ {
			shareDistributionTask, disputeMissingShareDistributionTask, disputeShareDistTask := events.UpdateStateOnRegistrationComplete(dkgStates[idx], height)

			shareDistributionTasks[idx] = shareDistributionTask
			disputeMissingShareDistributionTasks[idx] = disputeMissingShareDistributionTask
			disputeShareDistTasks[idx] = disputeShareDistTask[0]
		}

		// skip all the way to ShareDistribution phase
		AdvanceTo(t, eth, shareDistributionTasks[0].Start)
	} else {
		// this means some validators did not register, and the next phase is DisputeMissingRegistration
		AdvanceTo(t, eth, dkgStates[0].PhaseStart+dkgStates[0].PhaseLength)
	}

	return &TestSuite{
		Eth:                          eth,
		DKGStates:                    dkgStates,
		ecdsaPrivateKeys:             ecdsaPrivateKeys,
		regTasks:                     regTasks,
		DispMissingRegTasks:          dispMissingRegTasks,
		ShareDistTasks:               shareDistributionTasks,
		DisputeMissingShareDistTasks: disputeMissingShareDistributionTasks,
		DisputeShareDistTasks:        disputeShareDistTasks,
	}
}

func StartFromShareDistributionPhase(t *testing.T, n int, undistributedSharesIdx []int, badSharesIdx []int, phaseLength uint16) *TestSuite {
	suite := StartFromRegistrationOpenPhase(t, n, 0, phaseLength)
	ctx := context.Background()
	logger := logging.GetLogger("test").WithField("Validator", "")

	callOpts, err := suite.Eth.GetCallOpts(ctx, suite.Eth.GetDefaultAccount())
	assert.Nil(t, err)

	phase, err := ethereum.GetContracts().Ethdkg().GetETHDKGPhase(callOpts)
	assert.Nil(t, err)
	assert.Equal(t, phase, uint8(state.ShareDistribution))

	height, err := suite.Eth.GetCurrentHeight(ctx)
	assert.Nil(t, err)
	assert.GreaterOrEqual(t, height, suite.ShareDistTasks[0].Start)

	// Do Share Distribution task
	for idx := 0; idx < n; idx++ {
		state := suite.DKGStates[idx]

		var skipLoop = false

		for _, undistIdx := range undistributedSharesIdx {
			if idx == undistIdx {
				skipLoop = true
			}
		}

		if skipLoop {
			continue
		}

		shareDistTask := suite.ShareDistTasks[idx]

		// TODO - fix this
		err := shareDistTask.Initialize(ctx, nil, nil, logger, suite.Eth, "id", nil)
		assert.Nil(t, err)

		for _, badIdx := range badSharesIdx {
			if idx == badIdx {
				// inject bad shares
				for _, s := range state.Participants[state.Account.Address].EncryptedShares {
					s.Set(big.NewInt(0))
				}
			}
		}

		// TODO - fix this
		//err = shareDistTask.DoWork(ctx, logger, suite.Eth)
		//assert.Nil(t, err)
		//assert.True(t, shareDistTask.Success)

		// event
		for j := 0; j < n; j++ {
			// simulate receiving event for all participants
			err = suite.DKGStates[j].OnSharesDistributed(
				logger,
				state.Account.Address,
				state.Participants[state.Account.Address].EncryptedShares,
				state.Participants[state.Account.Address].Commitments,
			)
			assert.Nil(t, err)
		}

	}

	disputeShareDistributionTasks := make([]*dkg.DisputeShareDistributionTask, n)
	keyshareSubmissionTasks := make([]*dkg.KeyShareSubmissionTask, n)
	disputeMissingKeySharesTasks := make([]*dkg.DisputeMissingKeySharesTask, n)

	if len(undistributedSharesIdx) == 0 {
		height, err := suite.Eth.GetCurrentHeight(ctx)
		assert.Nil(t, err)
		var dispShareDistStartBlock uint64

		// this means all validators distributed their shares and now the phase is
		// set phase to DisputeShareDistribution
		for i := 0; i < n; i++ {
			disputeShareDistributionTask, keyshareSubmissionTask, disputeMissingKeySharesTask := events.UpdateStateOnShareDistributionComplete(suite.DKGStates[i], height)

			dispShareDistStartBlock = disputeShareDistributionTask[i].GetStart()

			disputeShareDistributionTasks[i] = disputeShareDistributionTask[i]
			keyshareSubmissionTasks[i] = keyshareSubmissionTask
			disputeMissingKeySharesTasks[i] = disputeMissingKeySharesTask
		}

		suite.DisputeShareDistTasks = disputeShareDistributionTasks
		suite.KeyshareSubmissionTasks = keyshareSubmissionTasks
		suite.DisputeMissingKeyshareTasks = disputeMissingKeySharesTasks

		// skip all the way to DisputeShareDistribution phase
		AdvanceTo(t, suite.Eth, dispShareDistStartBlock)
	} else {
		// this means some validators did not distribute shares, and the next phase is DisputeMissingShareDistribution
		AdvanceTo(t, suite.Eth, suite.DKGStates[0].PhaseStart+suite.DKGStates[0].PhaseLength)
	}

	return suite
}

func StartFromKeyShareSubmissionPhase(t *testing.T, n int, undistributedShares int, phaseLength uint16) *TestSuite {
	suite := StartFromShareDistributionPhase(t, n, []int{}, []int{}, phaseLength)
	ctx := context.Background()
	logger := logging.GetLogger("test").WithField("Validator", "")

	keyshareSubmissionStartBlock := suite.KeyshareSubmissionTasks[0].Start
	AdvanceTo(t, suite.Eth, keyshareSubmissionStartBlock)

	// Do key share submission task
	for idx := 0; idx < n; idx++ {
		state := suite.DKGStates[idx]

		if idx >= n-undistributedShares {
			continue
		}

		keyshareSubmissionTask := suite.KeyshareSubmissionTasks[idx]

		err := keyshareSubmissionTask.Initialize(ctx, nil, nil, logger, suite.Eth, "id", nil)
		//err := keyshareSubmissionTask.Initialize(ctx, logger, suite.Eth)
		assert.Nil(t, err)

		//TODO - Fix this
		//err = keyshareSubmissionTask.DoWork(ctx, logger, suite.Eth)
		//assert.Nil(t, err)
		//assert.True(t, keyshareSubmissionTask.Success)

		// event
		for j := 0; j < n; j++ {
			// simulate receiving event for all participants
			suite.DKGStates[j].OnKeyShareSubmitted(
				state.Account.Address,
				state.Participants[state.Account.Address].KeyShareG1s,
				state.Participants[state.Account.Address].KeyShareG1CorrectnessProofs,
				state.Participants[state.Account.Address].KeyShareG2s,
			)
		}
	}

	mpkSubmissionTasks := make([]*dkg.MPKSubmissionTask, n)

	if undistributedShares == 0 {
		// at this point all the validators submitted their key shares
		height, err := suite.Eth.GetCurrentHeight(ctx)
		assert.Nil(t, err)

		// this means all validators submitted their respective key shares and now the phase is
		// set phase to MPK
		var mpkSubmissionTaskStart uint64
		for i := 0; i < n; i++ {
			mpkSubmissionTask := events.UpdateStateOnKeyShareSubmissionComplete(suite.DKGStates[i], height)
			mpkSubmissionTaskStart = mpkSubmissionTask.GetStart()

			mpkSubmissionTasks[i] = mpkSubmissionTask
		}

		// skip all the way to MPKSubmission phase
		AdvanceTo(t, suite.Eth, mpkSubmissionTaskStart)
	} else {
		// this means some validators did not submit key shares, and the next phase is DisputeMissingKeyShares
		AdvanceTo(t, suite.Eth, suite.DKGStates[0].PhaseStart+suite.DKGStates[0].PhaseLength)
	}

	suite.MpkSubmissionTasks = mpkSubmissionTasks

	return suite
}

func StartFromMPKSubmissionPhase(t *testing.T, n int, phaseLength uint16) *TestSuite {
	suite := StartFromKeyShareSubmissionPhase(t, n, 0, phaseLength)
	ctx := context.Background()
	logger := logging.GetLogger("test").WithField("Validator", "")
	dkgStates := suite.DKGStates
	//eth := suite.Eth

	// Do MPK Submission task (once is enough)

	for idx := 0; idx < n; idx++ {
		task := suite.MpkSubmissionTasks[idx]
		//state := dkgStates[idx]
		err := task.Initialize(ctx, nil, nil, logger, suite.Eth, "id", nil)
		//err := task.Initialize(ctx, logger, eth)
		assert.Nil(t, err)
		// TODO - fix this
		//if task.AmILeading(ctx, eth, logger, state) {
		//	err = task.DoWork(ctx, logger, eth)
		//	assert.Nil(t, err)
		//}
	}

	height, err := suite.Eth.GetCurrentHeight(ctx)
	assert.Nil(t, err)

	gpkjSubmissionTasks := make([]*dkg.GPKjSubmissionTask, n)
	disputeMissingGPKjTasks := make([]*dkg.DisputeMissingGPKjTask, n)
	disputeGPKjTasks := make([]*dkg.DisputeGPKjTask, n)

	for idx := 0; idx < n; idx++ {
		state := dkgStates[idx]
		//TODO - fix this
		//gpkjSubmissionTask, disputeMissingGPKjTask, disputeGPKjTask := events.UpdateStateOnMPKSet(state, height, new(MockAdminHandler))
		gpkjSubmissionTask, disputeMissingGPKjTask, disputeGPKjTask := events.UpdateStateOnMPKSet(state, height, nil)

		gpkjSubmissionTasks[idx] = gpkjSubmissionTask
		disputeMissingGPKjTasks[idx] = disputeMissingGPKjTask
		disputeGPKjTasks[idx] = disputeGPKjTask[idx]
	}

	suite.GpkjSubmissionTasks = gpkjSubmissionTasks
	suite.DisputeMissingGPKjTasks = disputeMissingGPKjTasks
	suite.DisputeGPKjTasks = disputeGPKjTasks

	return suite
}

func StartFromGPKjPhase(t *testing.T, n int, undistributedGPKjIdx []int, badGPKjIdx []int, phaseLength uint16) *TestSuite {
	suite := StartFromMPKSubmissionPhase(t, n, phaseLength)
	ctx := context.Background()
	logger := logging.GetLogger("test").WithField("Validator", "")

	// Do GPKj Submission task
	for idx := 0; idx < n; idx++ {
		state := suite.DKGStates[idx]

		var skipLoop = false

		for _, undistIdx := range undistributedGPKjIdx {
			if idx == undistIdx {
				skipLoop = true
			}
		}

		if skipLoop {
			continue
		}

		gpkjSubTask := suite.GpkjSubmissionTasks[idx]

		err := gpkjSubTask.Initialize(ctx, nil, nil, logger, suite.Eth, "id", nil)
		//err := gpkjSubTask.Initialize(ctx, logger, suite.Eth)
		assert.Nil(t, err)

		for _, badIdx := range badGPKjIdx {
			if idx == badIdx {
				// inject bad shares
				// mess up with group private key (gskj)
				gskjBad := new(big.Int).Add(state.GroupPrivateKey, big.NewInt(1))
				// here's the group public key
				gpkj := new(cloudflare.G2).ScalarBaseMult(gskjBad)
				gpkjBad, err := bn256.G2ToBigIntArray(gpkj)
				assert.Nil(t, err)

				state.GroupPrivateKey = gskjBad
				state.Participants[state.Account.Address].GPKj = gpkjBad
			}
		}

		// TODO - fix this
		//err = gpkjSubTask.DoWork(ctx, logger, suite.Eth)
		//assert.Nil(t, err)
		//assert.True(t, gpkjSubTask.Success)

		// event
		for j := 0; j < n; j++ {
			// simulate receiving event for all participants
			suite.DKGStates[j].OnGPKjSubmitted(
				state.Account.Address,
				state.Participants[state.Account.Address].GPKj,
			)
		}

	}

	disputeGPKjTasks := make([]*dkg.DisputeGPKjTask, n)
	completionTasks := make([]*dkg.CompletionTask, n)

	if len(undistributedGPKjIdx) == 0 {
		height, err := suite.Eth.GetCurrentHeight(ctx)
		assert.Nil(t, err)
		var dispGPKjStartBlock uint64

		// this means all validators submitted their GPKjs and now the phase is
		// set phase to DisputeGPKjDistribution
		for i := 0; i < n; i++ {
			disputeGPKjTask, completionTask := events.UpdateStateOnGPKJSubmissionComplete(suite.DKGStates[i], height)

			dispGPKjStartBlock = disputeGPKjTask[0].GetStart()

			disputeGPKjTasks[i] = disputeGPKjTask[0]
			completionTasks[i] = completionTask
		}

		suite.DisputeGPKjTasks = disputeGPKjTasks
		suite.CompletionTasks = completionTasks

		// skip all the way to DisputeGPKj phase
		AdvanceTo(t, suite.Eth, dispGPKjStartBlock)
	} else {
		// this means some validators did not submit their GPKjs, and the next phase is DisputeMissingGPKj
		AdvanceTo(t, suite.Eth, suite.DKGStates[0].PhaseStart+suite.DKGStates[0].PhaseLength)
	}

	return suite
}

func StartFromCompletion(t *testing.T, n int, phaseLength uint16) *TestSuite {
	suite := StartFromGPKjPhase(t, n, []int{}, []int{}, phaseLength)

	// move to Completion phase
	AdvanceTo(t, suite.Eth, suite.CompletionTasks[0].Start+suite.DKGStates[0].ConfirmationLength)

	return suite
}
