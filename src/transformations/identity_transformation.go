package transformations

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// This circuit is only for Identity transformations.
// Public fields: PublicKey, ImageSignature
// Secret fields: ImageBytes
type IdentityCircuit struct {
	PublicKey      eddsa.PublicKey   `gnark:",public"`
	ImageSignature eddsa.Signature   `gnark:",public"`
	ImageBytes     frontend.Variable `gnark:","`
}

// Defines the Compliance Predicate for the IdentityCircuit, which is used to enforce Identity tranformations only,
// in this case. This function utilizes the frontend.API to verify the circuit's ImageSignature inside the
// Compliance Predicate, so secret fields remain secret when creating proofs or verifyin proofs.
func (circuit *IdentityCircuit) Define(api frontend.API) error {
	// Set the twisted edwards curve
	curve, err := twistededwards.NewEdCurve(api, 1)
	if err != nil {
		return err
	}

	// Get the hash function that can be used in verifying signatures inside a Gnark ZKP-circuit.
	// i.e. without revealing secret fields in the circuit.
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Verify the circuit's ImageSignature using a ZKP-circuit function for EdDSA signatures.
	// This involves using the same hash function MiMC(ImageBytes + public key) to generate a secondary
	// signature, and then verifying if the signatures match. This is done in a ZKP-circuit so the secret
	// fields are not revealed.
	eddsa.Verify(curve, circuit.ImageSignature, circuit.ImageBytes, circuit.PublicKey, &mimc)

	return nil
}
