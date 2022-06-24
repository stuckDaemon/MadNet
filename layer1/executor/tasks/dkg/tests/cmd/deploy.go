package cmd

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func RunDeploy(workingDir string) (string, error) {

	bridgeDir := GetBridgePath()
	_, _, err := executeCommand(bridgeDir, "npx", "hardhat --network dev setHardhatIntervalMining --enable-auto-mine")
	if err != nil {
		return "", err
	}

	_, output, err := executeCommand(bridgeDir, "npx", "hardhat --network dev --show-stack-traces deployContracts --input-folder", filepath.Join(workingDir))
	if err != nil {
		return "", err
	}
	firstLogLine := strings.Split(string(output), "\n")[0]
	addressLine := strings.Split(firstLogLine, ":")
	factoryAddress := strings.TrimSpace(addressLine[len(addressLine)-1])

	err = ReplaceOwnerRegistryAddress(workingDir, factoryAddress)
	if err != nil {
		return "", err
	}
	err = ReplaceValidatorsRegistryAddress(workingDir, factoryAddress)
	if err != nil {
		return "", err
	}

	// Replace filename

	_, _, err = executeCommand(bridgeDir, "npx", "hardhat --network dev fundValidators --config-path", filepath.Join(workingDir, "config"))
	if err != nil {
		return "", err
	}

	_, isSet := os.LookupEnv("SKIP_REGISTRATION")
	if isSet {
		return "", nil
	}

	_, _, err = executeCommand(bridgeDir, "npx", "hardhat --network dev setHardhatIntervalMining --interval 100")
	if err != nil {
		return "", err
	}

	// List of validators
	var validatorsAddressList []string
	files, err := ioutil.ReadDir(filepath.Join(workingDir, "keystores", "keys"))
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		if file.Name() == "0x546F99F244b7B58B855330AE0E2BC1b30b41302F" {
			continue
		}
		validatorsAddressList = append(validatorsAddressList, file.Name())
	}

	err = RunRegister(factoryAddress, validatorsAddressList)
	if err != nil {
		return "", err
	}

	_, _, err = executeCommand(bridgeDir, "npx", "hardhat --network dev setMinEthereumBlocksPerSnapshot --block-num 10 --factory-address", factoryAddress)
	if err != nil {
		return "", err
	}

	_, _, err = executeCommand(bridgeDir, "npx", "hardhat --network dev setHardhatIntervalMining")
	if err != nil {
		return "", err
	}

	//generatedValidatorConfigFiles := filepath.Join(workingDir, "scripts", "generated", "config")
	//files, _ := ioutil.ReadDir(generatedValidatorConfigFiles)
	//err = RunValidator(workingDir, len(files))
	//if err != nil {
	//	return "", err
	//}

	return factoryAddress, nil
}
