package camera

import (
	"fmt"
	gen "src/generator"
	myImage "src/image"
	"src/prover"
	myTransformations "src/transformations"
)

// A Secure Camera is not defined in the PhotoProof paper.
// A Camera has a "factory" secret key securely embedded with the Image Sensor Unit,
// as well as secure computation capabilities that would allow a camera to run
// Editor functionality.
type SecureCamera struct {
	secretKey  gen.SK_PP
	provingKey gen.PK_PP
	picture    myImage.I
}

// Simulate a secure camera taking a picture
func (cam *SecureCamera) TakePicture() {
	cam.picture = myImage.AllWhiteImage()
}

// Simulate a secure camera running the generator function
func (cam *SecureCamera) CameraGenerator() (gen.PK_PP, gen.VK_PP) {
	// Running the Generator function over the image, for the Identity transformation.
	fmt.Println("(Generator function STARTING...)")
	pk_PP, vk_PP, sk_PP, err := gen.Generator(cam.picture, "Identity")
	if err != nil {
		fmt.Printf("\nerror: %s", err.Error())
	}

	// Print the outputs of the Generator
	fmt.Println("(OUTPUT)")
	fmt.Printf("\nPK_PCD: %+v", pk_PP)
	fmt.Printf("\nVK_PCD: %+v", vk_PP)
	fmt.Printf("\nsecretKey: %+v", sk_PP)

	// Set keys in the camera
	cam.provingKey = pk_PP
	cam.secretKey = sk_PP

	// Return the proving key and verifying key to the public
	return pk_PP, vk_PP
}

// Simulate a secure camera running the editor function with the Identity transformation
func (cam *SecureCamera) CameraProof() (prover.Proof, myImage.Z) {
	signature := cam.picture.Sign(cam.secretKey.SecretKey)
	proof := prover.Proof{Digital_Sig: signature}
	z := myImage.Z{Image: cam.picture, PublicKey: cam.provingKey.PublicKey}

	return prover.Prover(cam.provingKey, z, proof, myTransformations.Transformation{T: "", Params: nil})
}
