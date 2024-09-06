package prover

import (
	"fmt"
	gen "src/generator"
	myImage "src/image"
	myTransformations "src/transformations"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type Proof struct {
	PCD_proof      groth16.Proof
	Z_in           myImage.Z
	Digital_Sig    []byte
	Public_Witness witness.Witness
}

// A prover is able to run a transformation on an image and
// if the proof_in is just a digital signature,
//
//	then create a groth16.Proof from the proving key (PK_PP.pk_PCD) and z_out
//
// else
//
//	the
func Prover(pk_pcd gen.PK_PP, z_in myImage.Z, proof_in Proof, t myTransformations.Transformation) (Proof, myImage.Z) {

	// No PCD Proof yet; this is the original image + a digital signature.
	if proof_in.PCD_proof == nil {
		// Generate a non-compile compliance predicate
		var compliance_predicate constraint.ConstraintSystem

		// Specifying which circuit we are using
		var circuit myTransformations.IdentityCircuit

		// Set circuit's public and secret fields
		// Assign the eddsa_signature into an eddsa.Signature
		var eddsa_signature eddsa.Signature
		eddsa_signature.Assign(1, proof_in.Digital_Sig)

		// Assign publicKey to an eddsa.PublicKey
		var eddsa_publicKey eddsa.PublicKey
		eddsa_publicKey.Assign(1, pk_pcd.PublicKey.Bytes())

		circuit.PublicKey = eddsa_publicKey
		circuit.ImageSignature = eddsa_signature
		circuit.ImageBytes = z_in.Image.ToBigEndian()

		// Dereferencing the circuit into a frontend.Circuit
		var frontendCircuit frontend.Circuit = &circuit

		// Construct the secret_witness BEFORE compiling
		secret_witness, err := frontend.NewWitness(frontendCircuit, ecc.BN254.ScalarField())
		if err != nil {
			fmt.Println("Error while creating Witness: \n" + err.Error() + "\n-----------------")
		}

		// When compiling a compliance_predicate (aka constraint system) in Gnark, we require:
		//        - elliptic curve (the security parameter of the bn254 curve has 254-bit prime number, 128-bit security)
		// 		  - R1CS builder (i.e. a frontend.builder interface)
		//        - a specific circuit (i.e. a circuit that has already undergone the NewWitness() function)
		compliance_predicate, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, frontendCircuit)
		if err != nil {
			fmt.Println(err.Error())
		}

		// use the witness directly in zk-SNARK backend APIs to create a proof_out
		proof_out, err := groth16.Prove(compliance_predicate, pk_pcd.ProvingKey, secret_witness)

		// Create public witness
		publicWitness, err := secret_witness.Public()
		if err != nil {
			fmt.Println("Error while creating Public Witness: \n" + err.Error() + "\n-----------------")
		}

		return Proof{PCD_proof: proof_out, Z_in: z_in, Public_Witness: publicWitness}, z_in
	}

	return Proof{}, myImage.Z{}
}
