package pvss

import (
	"math/big"

	"github.com/jinzhu/copier"
	"github.com/torusresearch/pvss/common"
	"github.com/torusresearch/pvss/secp256k1"
)

// Mobile Proactive Secret Sharing

// Generate random polynomial
// Note: this does not have a y-intercept of 0
func generateRandomPolynomial(threshold int) *common.PrimaryPolynomial {
	coeff := make([]big.Int, threshold)
	for i := 0; i < threshold; i++ { //randomly choose coeffs
		coeff[i] = *RandomBigInt()
	}
	return &common.PrimaryPolynomial{coeff, threshold}
}

func genPolyForTarget(x int, threshold int) *common.PrimaryPolynomial {
	tempPoly := generateRandomPolynomial(threshold)
	var poly common.PrimaryPolynomial
	copier.Copy(&poly, &tempPoly)
	valAtX := polyEval(*tempPoly, x)
	temp := new(big.Int).Sub(&poly.Coeff[0], valAtX)
	poly.Coeff[0].Mod(temp, secp256k1.GeneratorOrder)
	return &poly
}
