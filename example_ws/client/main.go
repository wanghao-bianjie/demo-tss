package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/ethereum/go-ethereum/crypto"
	"io/ioutil"
	"log"
	"math/big"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	golog "github.com/ipfs/go-log"
)

var (
	Ids        = []string{"spark", "user"}
	keys       = []uint64{1001, 1002}
	Moniker    = ""
	localIndex = 1
	destIndex  = 0

	participants = 2
	threshold    = 1

	upgrader = websocket.Upgrader{}
)

func main() {
	golog.SetLogLevel("tss-lib", "info")

	now := time.Now()
	log.Println("------------------------keygen start------------------------")
	fnkKeygen()
	log.Println("------------------------keygen end------------------------")

	log.Println("keygen cost(ms)", time.Since(now).Milliseconds())

	now = time.Now()
	log.Println("------------------------sign start------------------------")
	fnSign()
	log.Println("------------------------sign end------------------------")
	log.Println("sign cost(ms)", time.Since(now).Milliseconds())
}

func fnkKeygen() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := url.URL{Scheme: "ws", Host: "localhost:8881", Path: "/websocket/keygen"}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	updater := func(msg tss.Message, errCh chan<- *tss.Error) {
		marshal, err := proto.Marshal(msg.WireMsg())
		if err != nil {
			log.Fatal(err)
		}
		err = conn.WriteMessage(websocket.BinaryMessage, marshal)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("---->send to server")
	}

	preParam, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		log.Fatal(err)
	}

	var partyIDs = make([]*tss.PartyID, 0, participants)
	for i := 0; i < participants; i++ {
		partyIDs = append(partyIDs, tss.NewPartyID(Ids[i], Moniker, new(big.Int).SetUint64(keys[i])))
	}
	pIDs := tss.SortPartyIDs(partyIDs)
	p2pCtx := tss.NewPeerContext(pIDs)

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan keygen.LocalPartySaveData, len(pIDs))

	params := tss.NewParameters(tss.S256(), p2pCtx, partyIDs[localIndex], participants, threshold)
	P := keygen.NewLocalParty(params, outCh, endCh, *preParam).(*keygen.LocalParty) // Omit the last arg to compute the pre-params in round 1
	go func(p *keygen.LocalParty) {
		if err := p.Start(); err != nil {
			errCh <- err
		}
	}(P)

	go func() {
		for {
			// 读取服务端发送的消息
			_, read, err := conn.ReadMessage()
			if err != nil {
				log.Println(err)
				return
			}

			fmt.Println("<----receive from server")
			var msg tss.MessageWrapper
			err = proto.Unmarshal(read, &msg)
			if err != nil {
				log.Println(err)
			}
			bz, _ := proto.Marshal(msg.Message)
			ok, err := P.UpdateFromBytes(bz, partyIDs[destIndex], msg.IsBroadcast)
			log.Println("update result:", ok, err)
		}
	}()

keygen:
	for {
		select {
		case err := <-errCh:
			log.Fatal(err)
			return
		case msg := <-outCh:
			log.Println("msg", msg, msg.IsBroadcast())
			updater(msg, errCh)
		case save := <-endCh:
			log.Println("end!!!!")
			marshal, err := json.Marshal(save)
			if err != nil {
				log.Fatal(err)
			}
			file, err := os.Create(fmt.Sprintf("example_ws/client/%d-%s.json", localIndex, Ids[localIndex]))
			if err != nil {
				log.Fatal(err)
			}
			file.Write(marshal)
			file.Close()
			break keygen
		}
	}

	err = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Println(err)
		return
	}
}

func fnSign() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := url.URL{Scheme: "ws", Host: "localhost:8881", Path: "/websocket/sign"}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	updater := func(msg tss.Message, errCh chan<- *tss.Error) {
		marshal, err := proto.Marshal(msg.WireMsg())
		if err != nil {
			log.Fatal(err)
		}
		err = conn.WriteMessage(websocket.BinaryMessage, marshal)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("---->send to server")
	}

	decodeString, err := hex.DecodeString("b42ca4636f721c7a331923e764587e98ec577cea1a185f60dfcc14dbb9bd900b")
	if err != nil {
		log.Fatal(err)
	}
	signMsg := new(big.Int).SetBytes(decodeString)
	var partyIDs = make([]*tss.PartyID, 0, participants)
	for i := 0; i < participants; i++ {
		partyIDs = append(partyIDs, tss.NewPartyID(Ids[i], Moniker, new(big.Int).SetUint64(keys[i])))
	}
	pIDs := tss.SortPartyIDs(partyIDs)
	p2pCtx := tss.NewPeerContext(pIDs)

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan common.SignatureData, len(pIDs))

	var key keygen.LocalPartySaveData
	readFile, err := ioutil.ReadFile(fmt.Sprintf("example_ws/client/%d-%s.json", localIndex, Ids[localIndex]))
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(readFile, &key)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("pk address", getPkAddress(key))

	params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[localIndex], len(pIDs), threshold)

	P := signing.NewLocalParty(signMsg, params, key, outCh, endCh).(*signing.LocalParty)
	go func(P *signing.LocalParty) {
		if err := P.Start(); err != nil {
			errCh <- err
		}
	}(P)

	go func() {
		for {
			// 读取服务端发送的消息
			messageType, read, err := conn.ReadMessage()
			if err != nil {
				log.Println(err)
				return
			}
			if messageType == websocket.CloseMessage {
				break
			}

			fmt.Println("<----receive from server")
			var msg tss.MessageWrapper
			err = proto.Unmarshal(read, &msg)
			if err != nil {
				log.Println(err)
			}
			bz, _ := proto.Marshal(msg.Message)
			ok, err := P.UpdateFromBytes(bz, partyIDs[destIndex], msg.IsBroadcast)
			log.Println("update result:", ok, err)
		}
	}()

signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			break signing

		case msg := <-outCh:
			log.Println("sign msg")
			updater(msg, errCh)

		case data := <-endCh:
			log.Println("sign end")
			signature := hex.EncodeToString(data.Signature) + hex.EncodeToString(data.SignatureRecovery)
			log.Println("0x" + signature)

			pkX, pkY := key.ECDSAPub.X(), key.ECDSAPub.Y()
			pk := ecdsa.PublicKey{
				Curve: tss.EC(),
				X:     pkX,
				Y:     pkY,
			}
			ok := ecdsa.Verify(&pk, signMsg.Bytes(), new(big.Int).SetBytes(data.R), new(big.Int).SetBytes(data.S))
			log.Println("verify", ok)
			break signing
		}
	}

	err = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Println(err)
		return
	}
}

func getPkAddress(key keygen.LocalPartySaveData) string {
	return crypto.PubkeyToAddress(*key.ECDSAPub.ToECDSAPubKey()).Hex()
}
