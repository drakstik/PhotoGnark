package generator

import (
	"crypto/rand"
	"fmt"

	myImage "src/image"
	myTransformations "src/transformations"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// As defined in the paper, VK_PP is an output of the Generator function; and inputs for the Prover and Verifier functions.
type VK_PP struct {
	VerifyingKey groth16.VerifyingKey // public PCD verifying key
	PublicKey    signature.PublicKey  // public digital signature key
}

type PK_PP struct {
	ProvingKey groth16.ProvingKey  // public PCD proving key (pk_PCD)
	PublicKey  signature.PublicKey // public digital signature key (p_s)
}

type SK_PP struct {
	SecretKey signature.Signer // Secret key stored by secure camera
}

func Sign(image myImage.I) ([]byte, signature.PublicKey, signature.Signer, []byte) {
	// 1. Generate a normal signature keys.
	secretKey, err := ceddsa.New(1, rand.Reader) // Generate a secret key for signing
	if err != nil {
		fmt.Println(err.Error())
	}

	publicKey := secretKey.Public() // Generate a public key for verifying

	// Instantiate hash function to be used when signing the image
	hFunc := hash.MIMC_BN254.New()

	// Sign the image as a big endian slice
	big_endian_bytes_Image := image.ToBigEndian() // encode image as big endian slice
	normalSignature, err := secretKey.Sign(big_endian_bytes_Image, hFunc)
	if err != nil {
		fmt.Println(err.Error())
	}

	return normalSignature, publicKey, secretKey, big_endian_bytes_Image
}

// Input: an image and one permissible transformation t (TODO: set/combination of permissible transformations T)
// Output: A proving key, a verification key and a signing key.
func Generator(image myImage.I, t myTransformations.Transformation) (PK_PP, VK_PP, SK_PP, error) {

	normalSignature, publicKey, secretKey, big_endian_bytes_Image := Sign(image)

	// Assign the eddsa_signature into an eddsa.Signature
	var eddsa_signature eddsa.Signature
	eddsa_signature.Assign(1, normalSignature)

	// Assign publicKey to an eddsa.PublicKey
	var eddsa_publicKey eddsa.PublicKey
	eddsa_publicKey.Assign(1, publicKey.Bytes())

	// 2. Compile a compliance predicate, depending on the permissible Transformation(s)
	var compliance_predicate constraint.ConstraintSystem // Generating a non-compile compliance predicate
	var err error

	frT := t.ToFr()

	// If the transformation is identity, then set the params accordingly
	// NOTE: This if statement is not necessary & should be moved to camera. Generator is predefined with allowed transformations
	//			due to the choice in type of circuit.
	if t.T == myTransformations.Identity {
		frT.Params.X0 = 0
		frT.Params.Y0 = 0
		frT.Params.X1 = myImage.N - 1
		frT.Params.Y1 = myImage.N - 1
	}

	// Specifying which circuit we are using
	var circuit myTransformations.CropCircuit

	// Set circuit's public and secret fields
	circuit.PublicKey = eddsa_publicKey
	circuit.ImageSignature = eddsa_signature
	circuit.ImageBytes = big_endian_bytes_Image
	circuit.FrImage = image.ToFrontendImage()
	circuit.CroppedImage_in = image.ToFrontendImage()
	circuit.Params = frT.Params

	// Dereferencing the
	var frontendCircuit frontend.Circuit = &circuit

	// When compiling a compliance_predicate (aka constraint system) in Gnark, we require:
	//        - a specific circuit,
	//        - elliptic curve (the security parameter of the bn254 curve has 254-bit prime number, 128-bit security)
	// 		  - R1CS builder (aka a frontend.builder interface)
	compliance_predicate, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, frontendCircuit)
	if err != nil {
		fmt.Println(err.Error())
	}

	// 3. Generate PCD keys from the compliance_predicate (A. one-time setup https://docs.gnark.consensys.io/HowTo/prove)
	provingKey, verifyingKey, err := groth16.Setup(compliance_predicate)
	if err != nil {
		fmt.Println(err.Error())
	}
	vk_PCD := VK_PP{VerifyingKey: verifyingKey, PublicKey: publicKey}
	pk_PCD := PK_PP{ProvingKey: provingKey, PublicKey: publicKey}

	return pk_PCD, vk_PCD, SK_PP{SecretKey: secretKey}, err
}
