package node

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func GeneratePrivateKeyWithPrefix(prefix string) (*ecdsa.PrivateKey, error) {
	for {
		privateKey, err := GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		privKeyBytes := crypto.FromECDSA(privateKey)
		hexKey := hex.EncodeToString(privKeyBytes)

		if strings.HasPrefix(hexKey, prefix) {
			return privateKey, nil
		}
	}
}

func PublicKeyFromPrivateKey(privateKey *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	return privateKey.Public().(*ecdsa.PublicKey), nil
}

func NodeIDFromPrivateKey(privateKey *ecdsa.PrivateKey) (enode.ID, error) {
	publicKey, err := PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return enode.ID{}, err
	}
	return NodeIDFromPublicKey(publicKey)
}

func NodeIDFromPublicKey(publicKey *ecdsa.PublicKey) (enode.ID, error) {
	return enode.PubkeyToIDV4(publicKey), nil
}

func GeneratePrivateKeyWithCustodyColumns(columns []uint64, columnCount uint64, subnetCount uint64) (*ecdsa.PrivateKey, error) {
	i := 0
	for {
		fmt.Println("Generating key", i)
		i++
		privateKey, err := GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		nodeID, err := NodeIDFromPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}

		custodyColumns, err := CustodyColumnsSlice(nodeID, uint64(len(columns)), columnCount, subnetCount)
		if err != nil {
			return nil, err
		}

		if slices.Equal(columns, custodyColumns) {
			return privateKey, nil
		}
	}
}
