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
	Z              myImage.Z
	ImageSignature []byte
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
func Prover(pk_pcd gen.PK_PP, verifyingKey groth16.VerifyingKey, proof_in Proof, t myTransformations.Transformation) Proof {
	// Generate a non-compile compliance predicate
	var compliance_predicate constraint.ConstraintSystem

	// No PCD Proof yet; this is the original image + a digital signature.
	if proof_in.PCD_proof == nil {
		// Set circuit's public and secret fields
		// Assign the eddsa_signature into an eddsa.Signature
		var eddsa_signature eddsa.Signature
		eddsa_signature.Assign(1, proof_in.ImageSignature)

		// Assign publicKey to an eddsa.PublicKey
		var eddsa_publicKey eddsa.PublicKey
		eddsa_publicKey.Assign(1, pk_pcd.PublicKey.Bytes())

		// Specifying which circuit we are using
		var circuit myTransformations.CropCircuit

		circuit.PublicKey = eddsa_publicKey
		circuit.ImageSignature = eddsa_signature
		circuit.ImageBytes = proof_in.Z.Image.ToBigEndian()
		circuit.FrImage = proof_in.Z.Image.ToFrontendImage()
		circuit.CroppedImage_in = proof_in.Z.Image.ToFrontendImage()
		circuit.Params = t.ToFr().Params

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
		if err != nil {
			fmt.Println("Error while creating Proof: \n" + err.Error() + "\n-----------------")
		}

		// Create public witness
		publicWitness, err := secret_witness.Public()
		if err != nil {
			fmt.Println("Error while creating Public Witness: \n" + err.Error() + "\n-----------------")
		}

		return Proof{PCD_proof: proof_out, Z: proof_in.Z, ImageSignature: proof_in.ImageSignature, Public_Witness: publicWitness}
	} else if t.T == myTransformations.Crop || t.T == myTransformations.Identity {

		frT := t.ToFr()

		// If the transformation is identity, then set the params accordingly
		if t.T == myTransformations.Identity {
			frT.Params.X0 = 0
			frT.Params.Y0 = 0
			frT.Params.X1 = myImage.N - 1
			frT.Params.Y1 = myImage.N - 1
		}

		// Verify the PCD proof.
		err := groth16.Verify(proof_in.PCD_proof, verifyingKey, proof_in.Public_Witness)
		if err != nil {
			// Invalid proof.
			fmt.Println("FAIL: Image did not pass verification against PCD Proof.")
		} else {
			// Valid proof.
			fmt.Println("SUCCESS: Image verified against PCD Proof.")
		}

		// Record the z_in
		z_in := proof_in.Z

		// Crop the image, using the parameters
		proof_in.Z.Image.Crop(frT.Params.X0.(int), frT.Params.Y0.(int), frT.Params.X1.(int), frT.Params.Y1.(int))

		// Sign image_out
		normalSignature, publicKey, _, big_endian_bytes_Image := gen.Sign(proof_in.Z.Image)

		z_out := myImage.Z{Image: proof_in.Z.Image, PublicKey: publicKey}

		// Assign the eddsa_signature into an eddsa.Signature
		var eddsa_signature eddsa.Signature
		eddsa_signature.Assign(1, normalSignature)

		// Assign publicKey to an eddsa.PublicKey
		var eddsa_publicKey eddsa.PublicKey
		eddsa_publicKey.Assign(1, publicKey.Bytes())

		// Create the CropCiruit
		circuit := myTransformations.CropCircuit{
			PublicKey:       eddsa_publicKey,        // This is done redundantly to handle the final assert
			ImageSignature:  eddsa_signature,        // This is done redundantly
			ImageBytes:      big_endian_bytes_Image, // This is done redundantly
			FrImage:         z_in.Image.ToFrontendImage(),
			CroppedImage_in: z_out.Image.ToFrontendImage(),
			Params:          frT.Params,
		}

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
		if err != nil {
			fmt.Println("Error while creating Proof: \n" + err.Error() + "\n-----------------")
		}

		// Create public witness
		publicWitness, err := secret_witness.Public()
		if err != nil {
			fmt.Println("Error while creating Public Witness: \n" + err.Error() + "\n-----------------")
		}

		return Proof{PCD_proof: proof_out, Z: z_out, Public_Witness: publicWitness}
	}

	return Proof{}
}
