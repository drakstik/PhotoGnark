package verifier

import (
	"fmt"
	"src/generator"
	"src/prover"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
)

func Verifier(vk_pp generator.VK_PP, proof prover.Proof) bool {
	if proof.PCD_proof == nil {
		// Encode image.
		msg := proof.Z.Image.ToByte() // []byte{0xde, 0xad, 0xf0, 0x0d, 0x0d}

		// The size of the message must be a multiple of the size of Fr or you can get runtime error:
		// "runtime error: slice bounds out of range"
		var msgFr fr.Element
		msgFr.SetBytes(msg)   // Set z value for the fr.Element
		msg = msgFr.Marshal() // Convert z value to a big endian slice

		// Instantiate hash function.
		hFunc := hash.MIMC_BN254.New()

		// Verify digital signature.
		isVerified, err := vk_pp.PublicKey.Verify(proof.ImageSignature, msg, hFunc)
		if err != nil {
			fmt.Println(err.Error())
		}

		if isVerified {
			fmt.Println("SUCCESS: Image verified against original image's Digital Signature.")
			return true
		} else {
			fmt.Println("FAIL: Image did not pass verification against original image's Digital Signature.")
		}
	} else {
		// Verify the PCD proof.
		err := groth16.Verify(proof.PCD_proof, vk_pp.VerifyingKey, proof.Public_Witness)
		if err != nil {
			// Invalid proof.
			fmt.Println("FAIL: Image did not pass verification against PCD Proof.")
		} else {
			// Valid proof.
			fmt.Println("SUCCESS: Image verified against PCD Proof.")
			return true
		}
	}

	return false
}
