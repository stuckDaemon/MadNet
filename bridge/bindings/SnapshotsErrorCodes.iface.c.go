// Generated by ifacemaker. DO NOT EDIT.

package bindings

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

// ISnapshotsErrorCodesCaller ...
type ISnapshotsErrorCodesCaller interface {
	// SNAPSHOTCALLERNOTETHDKGPARTICIPANT is a free data retrieval call binding the contract method 0xadcb3a44.
	//
	// Solidity: function SNAPSHOT_CALLER_NOT_ETHDKG_PARTICIPANT() view returns(bytes32)
	SNAPSHOTCALLERNOTETHDKGPARTICIPANT(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTCONSENSUSRUNNING is a free data retrieval call binding the contract method 0x8d17de64.
	//
	// Solidity: function SNAPSHOT_CONSENSUS_RUNNING() view returns(bytes32)
	SNAPSHOTCONSENSUSRUNNING(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTINCORRECTBLOCKHEIGHT is a free data retrieval call binding the contract method 0x0c24555d.
	//
	// Solidity: function SNAPSHOT_INCORRECT_BLOCK_HEIGHT() view returns(bytes32)
	SNAPSHOTINCORRECTBLOCKHEIGHT(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTINCORRECTCHAINID is a free data retrieval call binding the contract method 0x3f772c6f.
	//
	// Solidity: function SNAPSHOT_INCORRECT_CHAIN_ID() view returns(bytes32)
	SNAPSHOTINCORRECTCHAINID(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTMIGRATIONINPUTDATAMISMATCH is a free data retrieval call binding the contract method 0x9854bdc5.
	//
	// Solidity: function SNAPSHOT_MIGRATION_INPUT_DATA_MISMATCH() view returns(bytes32)
	SNAPSHOTMIGRATIONINPUTDATAMISMATCH(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTMIGRATIONNOTALLOWED is a free data retrieval call binding the contract method 0x4f2adaee.
	//
	// Solidity: function SNAPSHOT_MIGRATION_NOT_ALLOWED() view returns(bytes32)
	SNAPSHOTMIGRATIONNOTALLOWED(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTMINBLOCKSINTERVALNOTPASSED is a free data retrieval call binding the contract method 0x4a1ec2ee.
	//
	// Solidity: function SNAPSHOT_MIN_BLOCKS_INTERVAL_NOT_PASSED() view returns(bytes32)
	SNAPSHOTMINBLOCKSINTERVALNOTPASSED(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTONLYVALIDATORSALLOWED is a free data retrieval call binding the contract method 0x83d995fa.
	//
	// Solidity: function SNAPSHOT_ONLY_VALIDATORS_ALLOWED() view returns(bytes32)
	SNAPSHOTONLYVALIDATORSALLOWED(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTSIGNATUREVERIFICATIONFAILED is a free data retrieval call binding the contract method 0x1d449ed1.
	//
	// Solidity: function SNAPSHOT_SIGNATURE_VERIFICATION_FAILED() view returns(bytes32)
	SNAPSHOTSIGNATUREVERIFICATIONFAILED(opts *bind.CallOpts) ([32]byte, error)
	// SNAPSHOTWRONGMASTERPUBLICKEY is a free data retrieval call binding the contract method 0x85c9dba1.
	//
	// Solidity: function SNAPSHOT_WRONG_MASTER_PUBLIC_KEY() view returns(bytes32)
	SNAPSHOTWRONGMASTERPUBLICKEY(opts *bind.CallOpts) ([32]byte, error)
}