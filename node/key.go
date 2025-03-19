package node

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

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

func GeneratePrivateKeyWithCustodyColumns(columns []uint64, columnCount uint64, subnetCount uint64, numWorkers int) (*ecdsa.PrivateKey, error) {
	startTime := time.Now()
	attempts := int64(0)
	resultChan := make(chan *ecdsa.PrivateKey, 1)
	errorChan := make(chan error, 1)
	stopChan := make(chan struct{})

	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			for {
				select {
				case <-stopChan:
					return
				default:
					atomic.AddInt64(&attempts, 1)
					if attempts%1000000 == 0 {
						elapsed := time.Since(startTime)
						rate := float64(attempts) / elapsed.Seconds()
						fmt.Printf("Attempts: %d, Time: %v, Rate: %.2f keys/sec\n", attempts, elapsed.Round(time.Second), rate)
					}

					privateKey, err := GeneratePrivateKey()
					if err != nil {
						errorChan <- err
						return
					}

					nodeID, err := NodeIDFromPrivateKey(privateKey)
					if err != nil {
						errorChan <- err
						return
					}

					custodyColumns, err := CustodyColumnsSlice(nodeID, uint64(len(columns)), columnCount, subnetCount)
					if err != nil {
						errorChan <- err
						return
					}

					if slices.Equal(columns, custodyColumns) {
						resultChan <- privateKey
						return
					}
				}
			}
		}(i)
	}

	// Wait for result or error
	select {
	case privateKey := <-resultChan:
		close(stopChan) // Stop other workers
		return privateKey, nil
	case err := <-errorChan:
		close(stopChan) // Stop other workers
		return nil, err
	}
}
