package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/ipfs/go-log"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

func main() {
	log.SetLogLevel("tss-lib", "info")

	updater := test.SharedPartyUpdater
	//nowUnix := time.Now().Unix()

	users := []string{"spark", "customer"}
	participants := len(users)
	threshold := 1

	var keys []keygen.LocalPartySaveData

	// When using the keygen party it is recommended that you pre-compute the "safe primes" and Paillier secret beforehand because this can take some time.
	// This code will generate those parameters using a concurrency limit equal to the number of available CPU cores.
	//preParams, err := keygen.GeneratePreParams(1 * time.Minute)
	//if err != nil {
	//	panic(err)
	//}

	// Create a `*PartyID` for each participating peer on the network (you should call `tss.NewPartyID` for each one)

	getParticipantPartyIDs := func() []*tss.PartyID {
		var partyIDs = make([]*tss.PartyID, 0, participants)
		for i := 1; i <= participants; i++ {
			// Set up the parameters
			// Note: The `id` and `moniker` fields are for convenience to allow you to easily track participants.
			// The `id` should be a unique string representing this party in the network and `moniker` can be anything (even left blank).
			// The `uniqueKey` is a unique identifying key for this peer (such as its p2p public key) as a big.Int.
			partyIDs = append(partyIDs, tss.NewPartyID(strconv.Itoa(i), strconv.Itoa(i), new(big.Int).SetInt64(time.Now().UnixNano()-int64(i))))
		}
		return partyIDs
	}
	pIDs := tss.SortPartyIDs(getParticipantPartyIDs())
	//pIDs := tss.GenerateTestPartyIDs(participants)

	// You should keep a local mapping of `id` strings to `*PartyID` instances so that an incoming message can have its origin party's `*PartyID` recovered for passing to `UpdateFromBytes` (see below)
	partyIDMap := make(map[string]*tss.PartyID)
	for _, id := range pIDs {
		partyIDMap[id.Id] = id
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	// Select an elliptic curve
	// use ECDSA
	curve := tss.S256()
	// or use EdDSA
	// curve := tss.Edwards()

	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan keygen.LocalPartySaveData, len(pIDs))

	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(curve, p2pCtx, pIDs[i], len(pIDs), threshold)
		P := keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty) // Omit the last arg to compute the pre-params in round 1
		parties = append(parties, P)
		go func(p *keygen.LocalParty) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			return
		case msg := <-outCh:
			fmt.Println("msg String:", msg.String())
			fmt.Println("msg GetFrom:", msg.GetFrom())
			fmt.Println("msg Type:", msg.Type())
			fmt.Println("msg GetTo:", msg.GetTo())
			fmt.Println("msg IsBroadcast:", msg.IsBroadcast())
			fmt.Println("msg IsToOldAndNewCommittees:", msg.IsToOldAndNewCommittees())
			fmt.Println("msg IsToOldCommittee:", msg.IsToOldCommittee())

			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					fmt.Printf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}
		case save := <-endCh:
			atomic.AddInt32(&ended, 1)
			keys = append(keys, save)
			fmt.Println("save:", save)
			marshal, err := json.Marshal(save)
			if err != nil {
				panic(err)
			}
			originalIndex, err := save.OriginalIndex()
			if err != nil {
				panic(err)
			}
			file, err := os.Create(fmt.Sprintf("keys/%s.json", users[originalIndex]))
			if err != nil {
				panic(err)
			}
			file.Write(marshal)
			file.Close()

			if ended == int32(len(pIDs)) {
				break keygen
			}
			// build ecdsa key pair
			//pkX, pkY := save.ECDSAPub.X(), save.ECDSAPub.Y()
			//pk := ecdsa.PublicKey{
			//	Curve: tss.EC(),
			//	X:     pkX,
			//	Y:     pkY,
			//}
			//sk := ecdsa.PrivateKey{
			//	PublicKey: pk,
			//	D:         u,
			//}
		}
	}

	signingParties := make([]*signing.LocalParty, 0, len(pIDs))

	signingOutCh := make(chan tss.Message, len(pIDs))
	signingEndCh := make(chan common.SignatureData, len(pIDs))
	signMsg := new(big.Int).SetBytes([]byte("hello"))
	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)

		P := signing.NewLocalParty(signMsg, params, keys[i], signingOutCh, signingEndCh).(*signing.LocalParty)
		signingParties = append(signingParties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	ended = 0
	sumS := big.NewInt(0)
	modN := common.ModInt(tss.S256().Params().N)
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			break signing

		case msg := <-signingOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signingParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					fmt.Printf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(signingParties[dest[0].Index], msg, errCh)
			}

		case data := <-signingEndCh:
			fmt.Println(new(big.Int).SetBytes(data.R).String())
			fmt.Println(new(big.Int).SetBytes(data.S).String())
			atomic.AddInt32(&ended, 1)
			sumS = modN.Add(sumS, new(big.Int).SetBytes(data.S))
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				// BEGIN check s correctness
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, signMsg.Bytes(), new(big.Int).SetBytes(data.R), new(big.Int).SetBytes(data.S))
				fmt.Println("verify", ok)
				// END ECDSA verify

				break signing
			}
		}
	}
}
