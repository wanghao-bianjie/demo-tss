package example_tcp

import (
	"encoding/json"
	"fmt"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/golang/protobuf/proto"
	"github.com/ipfs/go-log"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

var (
	Ids     = []string{"spark", "user"}
	keys    = []uint64{1001, 1002}
	Moniker = ""

	participants = 2
	threshold    = 1
)

func TestKeygenPeer1(t *testing.T) {
	localAddr := "0.0.0.0:8881"
	destAddr := "127.0.0.1:8882"
	fnKeygen(localAddr, destAddr, 0, 1, t)
}

func TestKeygenPeer2(t *testing.T) {
	localAddr := "0.0.0.0:8882"
	destAddr := "127.0.0.1:8881"
	fnKeygen(localAddr, destAddr, 1, 0, t)
}

func fnKeygen(localAddr, destAddr string, localIndex, destIndex int, t *testing.T) {
	time.Sleep(2 * time.Second)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	updater := func(msg tss.Message, errCh chan<- *tss.Error) {
		conn, err := net.Dial("tcp", destAddr)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		marshal, err := proto.Marshal(msg.WireMsg())
		if err != nil {
			t.Error(err)
		}
		_, err = conn.Write(marshal)
		if err != nil {
			t.Error(err)
		}
		t.Log("---->send")
	}

	log.SetLogLevel("tss-lib", "info")
	var key keygen.LocalPartySaveData

	preParam, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		t.Fatal(err)
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
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Log("<----receive")
			read, err := ioutil.ReadAll(conn)
			if err != nil {
				t.Error(err)
				return
			}

			var msg tss.MessageWrapper
			err = proto.Unmarshal(read, &msg)
			if err != nil {
				t.Error(err)
			}
			bz, _ := proto.Marshal(msg.Message)
			ok, err := P.UpdateFromBytes(bz, partyIDs[destIndex], msg.IsBroadcast)
			t.Log("update result:", ok, err)
		}

	}()

keygen:
	for {
		select {
		case err := <-errCh:
			t.Error(err)
			return
		case msg := <-outCh:
			t.Log("msg!!!!")
			t.Log(msg)
			t.Log(msg.IsBroadcast())
			go updater(msg, errCh)
		case save := <-endCh:
			t.Log("end!!!!")
			key = save
			break keygen
		}
	}

	marshal, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(fmt.Sprintf("%d-%s.json", localIndex, Ids[localIndex]))
	if err != nil {
		t.Fatal(err)
	}
	file.Write(marshal)
	file.Close()
}
