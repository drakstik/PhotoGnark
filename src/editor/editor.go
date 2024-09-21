package editor

import (
	generator "src/generator"
	prover "src/prover"
	myTransformations "src/transformations"

	"github.com/consensys/gnark/backend/groth16"
)

func EditorCrop(pk_pcd generator.PK_PP, verifyingKey groth16.VerifyingKey, proof prover.Proof, params map[string]int) prover.Proof {
	return prover.Prover(pk_pcd, verifyingKey, proof, myTransformations.Transformation{T: myTransformations.Crop, Params: params})
}
