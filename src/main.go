package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/torusresearch/pvss/common"
	"github.com/torusresearch/pvss/pvss"
	"github.com/torusresearch/pvss/secp256k1"
	"math/big"
)
type nodeList struct {
	Nodes []common.Node
}
func RandomBigInt() *big.Int {
	randomInt, _ := rand.Int(rand.Reader, secp256k1.GeneratorOrder)
	return randomInt
}
func HashToBigInt(s string) *big.Int {
	rst, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hash : " + s)
	}
	return rst
}
func createRandomNodes(number int) (*nodeList, []big.Int) {
	list := new(nodeList)
	privateKeys := make([]big.Int, number)
	for i := 0; i < number; i++ {
		skey := RandomBigInt()
		list.Nodes = append(list.Nodes, common.Node{
			i + 1,
			common.BigIntToPoint(secp256k1.Curve.ScalarBaseMult(skey.Bytes())),
		})
		privateKeys[i] = *skey
	}
	return list, privateKeys
}
func getHash(pre string) string {
	hash:=sha256.New()
	hash.Write([]byte(pre))
	return hex.EncodeToString(hash.Sum(nil))
}
func main()  {
    //compute a secret
	message:="Columbus"
	hashHex:=getHash(message)
	fmt.Println("pre secret:\n",hashHex)
	fmt.Println()
	secret:=HashToBigInt(hashHex)

    //setup
	nodeList, privateKeys := createRandomNodes(20)
	privKeySender := RandomBigInt()
	pubKeySender := common.BigIntToPoint(secp256k1.Curve.ScalarBaseMult(privKeySender.Bytes()))

    //compute shares
	signcryptedShares, _, err := pvss.CreateAndPrepareShares(nodeList.Nodes, *secret, 10, *privKeySender)
	if err != nil {
		fmt.Println(err)
	}

	//use the top ten to recover. if threshold>=10, success; else error.
	decryptedShares := make([]common.PrimaryShare, 10)
	for i := range decryptedShares {
		decryptedShare, err := pvss.UnsigncryptShare(signcryptedShares[i].SigncryptedShare, privateKeys[i], pubKeySender)

		if err != nil {
			fmt.Println(err)
		}
		decryptedShares[i] = common.PrimaryShare{i + 1, *new(big.Int).SetBytes(*decryptedShare)}
		fmt.Printf("partition %d: %v\n",i+1,*decryptedShare)
	}

    //a recovered result
	rst := pvss.LagrangeScalar(decryptedShares, 0)
	fmt.Println("\nrecovered secret:\n",rst.Text(16))
}
