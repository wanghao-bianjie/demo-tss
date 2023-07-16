package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ipfs/go-log"
	"io/ioutil"
	"math/big"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

var (
	users = []string{
		"spark",
		"user",
		//"customer3",
		//"customer4",
		//"customer5",
	}
	uniqueKeys = []uint64{
		1001,
		1002,
		//100003,
		//100004,
		//100005,
	}
	//2
	//2
	participants = len(users)
	threshold    = len(users) / 2

	signCount = threshold + 1
)

func TestKeyGen(t *testing.T) {
	//log.SetLogLevel("tss-lib", "info")

	updater := test.SharedPartyUpdater
	//nowUnix := time.Now().Unix()

	var keys []keygen.LocalPartySaveData

	// When using the keygen party it is recommended that you pre-compute the "safe primes" and Paillier secret beforehand because this can take some time.
	// This code will generate those parameters using a concurrency limit equal to the number of available CPU cores.
	var preParams []keygen.LocalPreParams
	for i := 0; i < participants; i++ {
		preParam, err := keygen.GeneratePreParams(1 * time.Minute)
		if err != nil {
			panic(err)
		}
		preParams = append(preParams, *preParam)
	}

	// Create a `*PartyID` for each participating peer on the network (you should call `tss.NewPartyID` for each one)

	getParticipantPartyIDs := func() []*tss.PartyID {
		var partyIDs = make([]*tss.PartyID, 0, participants)
		for i := 0; i < participants; i++ {
			// Set up the parameters
			// Note: The `id` and `moniker` fields are for convenience to allow you to easily track participants.
			// The `id` should be a unique string representing this party in the network and `moniker` can be anything (even left blank).
			// The `uniqueKey` is a unique identifying key for this peer (such as its p2p public key) as a big.Int.
			partyIDs = append(partyIDs, tss.NewPartyID(users[i], users[i], new(big.Int).SetUint64(uniqueKeys[i])))
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
		P := keygen.NewLocalParty(params, outCh, endCh, preParams[i]).(*keygen.LocalParty) // Omit the last arg to compute the pre-params in round 1
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
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			return
		case msg := <-outCh:
			t.Log("msg String:", msg.String())
			t.Log("msg GetFrom:", msg.GetFrom())
			t.Log("msg Type:", msg.Type())
			t.Log("msg GetTo:", msg.GetTo())
			t.Log("msg IsBroadcast:", msg.IsBroadcast())
			t.Log("msg IsToOldAndNewCommittees:", msg.IsToOldAndNewCommittees())
			t.Log("msg IsToOldCommittee:", msg.IsToOldCommittee())

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
			t.Log("save:", save)
			marshal, err := json.Marshal(save)
			if err != nil {
				panic(err)
			}
			originalIndex, err := save.OriginalIndex()
			if err != nil {
				panic(err)
			}
			file, err := os.Create(fmt.Sprintf("keys/%d-%s.json", originalIndex, users[originalIndex]))
			if err != nil {
				panic(err)
			}
			file.Write(marshal)
			file.Close()

			if ended == int32(len(pIDs)) {

				// build ecdsa key pair
				pkX, pkY := save.ECDSAPub.X(), save.ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				t.Log("verify:", pk)
				//publicKeyBytes := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
				//crypto.Keccak256Hash(publicKeyBytes[1:])
				//hash.Write(publicKeyBytes[1:]) // 去除前缀字节 0x04
				//hashed := hash.Sum(nil)

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
}

func TestSign(t *testing.T) {
	log.SetLogLevel("tss-lib", "info")
	decodeString, err := hex.DecodeString("b42ca4636f721c7a331923e764587e98ec577cea1a185f60dfcc14dbb9bd900b")
	if err != nil {
		t.Fatal(err)
	}
	signMsg := new(big.Int).SetBytes(decodeString)
	//signMsg := new(big.Int).SetBytes([]byte("hello"))

	updater := test.SharedPartyUpdater

	getParticipantPartyIDs := func() []*tss.PartyID {
		var partyIDs = make([]*tss.PartyID, 0, participants)
		for i := 0; i < signCount; i++ {
			// Set up the parameters
			// Note: The `id` and `moniker` fields are for convenience to allow you to easily track participants.
			// The `id` should be a unique string representing this party in the network and `moniker` can be anything (even left blank).
			// The `uniqueKey` is a unique identifying key for this peer (such as its p2p public key) as a big.Int.
			partyIDs = append(partyIDs, tss.NewPartyID(users[i], users[i], new(big.Int).SetUint64(uniqueKeys[i])))
		}
		return partyIDs
	}
	pIDs := tss.SortPartyIDs(getParticipantPartyIDs())

	p2pCtx := tss.NewPeerContext(pIDs)

	var keys []keygen.LocalPartySaveData
	for i := 0; i < signCount; i++ {
		readFile, err := ioutil.ReadFile(fmt.Sprintf("keys/%d-%s.json", i, users[i]))
		if err != nil {
			t.Fatal(err)
		}
		var key keygen.LocalPartySaveData
		err = json.Unmarshal(readFile, &key)
		if err != nil {
			t.Fatal(err)
		}
		//for _, kbxj := range key.BigXj {
		//	kbxj.SetCurve(tss.S256())
		//}
		//key.ECDSAPub.SetCurve(tss.S256())
		t.Log("pk address", getPkAddress(key))
		keys = append(keys, key)
	}

	signingParties := make([]*signing.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	signingOutCh := make(chan tss.Message, len(pIDs))
	signingEndCh := make(chan common.SignatureData, len(pIDs))
	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)

		P := signing.NewLocalParty(signMsg, params, keys[i], signingOutCh, signingEndCh).(*signing.LocalParty)
		//P := signing.NewLocalParty(nil, params, keys[i], signingOutCh, signingEndCh).(*signing.LocalParty)
		signingParties = append(signingParties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32 = 0
signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			break signing

		case msg := <-signingOutCh:
			//t.Log(msg.WireMsg())
			t.Log("sign msg")
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
			//GG20
			//data

			//
			t.Log("sign end")
			t.Log(new(big.Int).SetBytes(data.R).String())
			t.Log(new(big.Int).SetBytes(data.S).String())
			//t.Log(toEthSign(data.R, data.S))
			signature := hex.EncodeToString(data.Signature) + hex.EncodeToString(data.SignatureRecovery)
			t.Log("0x" + signature)

			//bz, _ := hex.DecodeString(signature)
			//ecrecover, err := crypto.Ecrecover(decodeString, bz)
			//if err != nil {
			//	t.Error(err)
			//} else {
			//	t.Log("ecrecover to address", ethcommon.BytesToAddress(ecrecover).Hex())
			//}

			//db4b01a421603d43725052fde7bc525f65ec4d0773a6e7fdb8cce6fa251ebdcc0a3304952628c90f3ed5026f55f4717c1f175cd290f860544df7e4f4a8d1b342
			//390d704d7ab732ce034203599ee93dd5d3cb0d4d1d7c600ac11726659489773d559b12d220f99f41d17651b0c1c6a669d346a397f8541760d6b32a5725378b241c
			//59cd4f7dfb3dc10ccc7ab270d0769242efade8d8cc0f4c0216aebf54240f23981b41ef38ae53b5fce1f6098b47a4fd7551dd09eb4ae78df946ab0747ddc360281b
			//
			atomic.AddInt32(&ended, 1)
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
				t.Log("verify", ok)
				// END ECDSA verify

				break signing
			}
		}
	}
}

func toEthSign(rBytes, sBytes []byte) string {
	if len(rBytes) < 32 {
		rBytes = append(make([]byte, 32-len(rBytes)), rBytes...)
	}
	if len(sBytes) < 32 {
		sBytes = append(make([]byte, 32-len(sBytes)), sBytes...)
	}

	signature := append(rBytes, sBytes...)
	return hex.EncodeToString(signature)
}

func getPkAddress(key keygen.LocalPartySaveData) string {
	return crypto.PubkeyToAddress(*key.ECDSAPub.ToECDSAPubKey()).Hex()
}

func TestPk(t *testing.T) {
	var key keygen.LocalPartySaveData
	file, err := ioutil.ReadFile("keys/0-customer1.json")
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(file, &key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(getPkAddress(key))
}

//恢复私钥
func TestReconstruct(t *testing.T) {
	var keys []keygen.LocalPartySaveData
	for i := 0; i < threshold+3; i++ {
		readFile, err := ioutil.ReadFile(fmt.Sprintf("keys/%d-%s.json", i, users[i]))
		if err != nil {
			t.Fatal(err)
		}
		var key keygen.LocalPartySaveData
		err = json.Unmarshal(readFile, &key)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(getPkAddress(key))
		keys = append(keys, key)
	}
	privateKey, err := reconstruct(threshold, tss.S256(), keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hex.EncodeToString(privateKey.D.Bytes()))
	msg := []byte("hello")
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ecdsa.Verify(keys[0].ECDSAPub.ToECDSAPubKey(), msg, r, s))
}

//恢复私钥
func reconstruct(threshold int, ec elliptic.Curve, shares []keygen.LocalPartySaveData) (*ecdsa.PrivateKey, error) {
	var vssShares = make(vss.Shares, len(shares))
	for i, share := range shares {
		vssShare := &vss.Share{
			Threshold: threshold,
			ID:        share.ShareID,
			Share:     share.Xi,
		}
		vssShares[i] = vssShare
	}

	d, err := vssShares.ReConstruct(ec)
	if err != nil {
		return nil, err
	}

	x, y := ec.ScalarBaseMult(d.Bytes())

	privateKey := &ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			Curve: ec,
			X:     x,
			Y:     y,
		},
	}

	return privateKey, nil
}
