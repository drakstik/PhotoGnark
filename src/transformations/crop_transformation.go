package transformations

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"

	myImage "src/image"
)

// This circuit is only for Crop transformations.
// Public fields: PublicKey, ImageSignature
// Secret fields: ImageBytes
type CropCircuit struct {
	PublicKey       eddsa.PublicKey       `gnark:",public"`
	ImageSignature  eddsa.Signature       `gnark:",public"` // Digital signature as eddsa.Signature
	ImageBytes      frontend.Variable     // z_in as Big Endian
	FrImage         myImage.FrontendImage // z_in as a FrontendImage
	CroppedImage_in myImage.FrontendImage // Cropped previous image as a FrontendImage
	Params          CropParams            // Crop transformation parameters
}

type CropParams struct {
	N  frontend.Variable
	X0 frontend.Variable
	Y0 frontend.Variable
	X1 frontend.Variable
	Y1 frontend.Variable
}

type Fr_SquareArea struct {
	topLeft     Fr_Location
	bottomRight Fr_Location
}

type Fr_Location struct {
	X frontend.Variable
	Y frontend.Variable
}

// Defines the Compliance Predicate for the IdentityCircuit, which is used to enforce Identity tranformations only,
// in this case. This function utilizes the frontend.API to verify the circuit's ImageSignature inside the
// Compliance Predicate, so secret fields remain secret when creating proofs or verifyin proofs.
func (circuit *CropCircuit) Define(api frontend.API) error {

	// Crop and translate the FRImage
	croppedImage_out := circuit.CropFrontendImage(api)

	// Assert the transformed_image_out and the transformed_image_in have equal pixels
	for x := 0; x < myImage.N; x++ {
		for y := 0; y < myImage.N; y++ {
			api.AssertIsEqual(
				circuit.CroppedImage_in.Pixels[x][y],
				croppedImage_out.Pixels[x][y],
			)
		}
	}

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

// CropFrontendImage crops and translates the FrontendImage using frontend.API and Compiler.
func (circuit *CropCircuit) CropFrontendImage(api frontend.API) myImage.FrontendImage {
	// Create constants for comparison (0, 1 & N) using Compiler
	zero, _ := api.Compiler().ConstantValue(0)
	one, _ := api.Compiler().ConstantValue(1)
	N := frontend.Variable(circuit.Params.N)
	N_minus_one := api.Sub(N, one)
	blackPixel := myImage.FrontendPixel{R: zero, G: zero, B: zero}

	oldImage := circuit.FrImage         // The previous image
	newImage := myImage.FrontendImage{} // The new image, to be set to transformed pixels

	// Area to crop,
	// {(X0,Y0), (X1, Y1)}
	cropArea := Fr_SquareArea{
		topLeft:     Fr_Location{X: circuit.Params.X0, Y: circuit.Params.Y0},
		bottomRight: Fr_Location{X: circuit.Params.X1, Y: circuit.Params.Y1},
	}

	// Area to bound pixels in,
	// {(0,0), (N-1, N-1)}
	imageBounds := Fr_SquareArea{
		topLeft:     Fr_Location{X: zero, Y: zero},
		bottomRight: Fr_Location{X: N_minus_one, Y: N_minus_one},
	}

	// Iterate over the entire N x N matrix

	for y := 0; y < myImage.N; y++ {
		for x := 0; x < myImage.N; x++ {
			xFr := frontend.Variable(x)
			yFr := frontend.Variable(y)

			// any pixels outside area should return false
			inCropArea := InArea(api, xFr, yFr, cropArea)

			// Calculate the new location
			newXFr := api.Sub(xFr, cropArea.topLeft.X)
			newX := newXFr.(int)

			newYFr := api.Sub(xFr, cropArea.topLeft.Y)
			newY := newYFr.(int)

			// any pixels outisde area should return false
			inBounds := InArea(api, newXFr, newYFr, imageBounds)

			// Get the current pixel
			currentPixel := oldImage.Pixels[x][y]

			// This essentially translates to:
			// 		if inBoundArea(newX, newY):
			//			if inCropArea(currentX, currentY):
			//				SELECT currentPixel
			//			else: SELECT blackPixel
			//		else: SELECT blackPixel
			//
			//	Where CropArea{(X0, Y1), (X1, Y1)} and BoundArea{(0,0), (N-1, N-1)}
			newImage.Pixels[newX][newY].R = api.Select(
				inBounds,
				api.Select(
					inCropArea,
					currentPixel.R,
					blackPixel.R,
				),
				blackPixel.R,
			)
			newImage.Pixels[newXFr.(int)][newYFr.(int)].G = api.Select(
				inBounds,
				api.Select(
					inCropArea,
					currentPixel.G,
					blackPixel.G,
				),
				blackPixel.G,
			)
			newImage.Pixels[newXFr.(int)][newYFr.(int)].B = api.Select(
				inBounds,
				api.Select(
					inCropArea,
					currentPixel.B,
					blackPixel.B,
				),
				blackPixel.B,
			)
		}
	}

	// TODO: Metadata updates for width and height
	// Update metadata to reflect the new dimensions of the cropped area
	// img.M["width"] = cropWidth
	// img.M["height"] = cropHeight

	return newImage
}

// InArea leverages the api.IsZero and api.Cmp() functions to return true if (x,y) are within the given area,
// false if not. The area bounds are included, i.e. all variables are index locations.
func InArea(api frontend.API, x frontend.Variable, y frontend.Variable, area Fr_SquareArea) frontend.Variable {

	// inCropAreaX translates to:
	// 		isZero(Cmp(area.topLeft.X, x))              ->   true if (topLeft.X == x)
	// 		isZero(Cmp(x, area.bottomRight.X))          ->   true if (x == bottomRight.X)
	// 		isZero(Cmp(area.topLeft.X, x) + 1)          ->   true if (topLeft.X < x)
	// 		isZero(Cmp(x, area.bottomRight.X) + 1)      ->   true if (x == bottomRight.X)
	inCropAreaX := api.And(
		api.And(
			api.IsZero(api.Cmp(area.topLeft.X, x)),
			api.IsZero(api.Cmp(x, area.bottomRight.X)),
		),
		api.And(
			api.IsZero(api.Add(api.Cmp(area.topLeft.X, x), 1)),
			api.IsZero(api.Add(api.Cmp(x, area.bottomRight.X), 1)),
		),
	)

	// inCropAreaY translates to:
	// 		isZero(Cmp(area.topLeft.Y, y))              ->   true if (topLeft.Y == y)
	// 		isZero(Cmp(y, area.bottomRight.Y))          ->   true if (y == bottomRight.Y)
	// 		isZero(Cmp(area.topLeft.Y, y) + 1)          ->   true if (topLeft.Y < y)
	// 		isZero(Cmp(y, area.bottomRight.Y) + 1)      ->   true if (y == bottomRight.Y)
	inCropAreaY := api.And(
		api.And(
			api.IsZero(api.Cmp(area.topLeft.Y, y)),
			api.IsZero(api.Cmp(y, area.bottomRight.Y)),
		),
		api.And(
			api.IsZero(api.Add(api.Cmp(area.topLeft.Y, y), 1)),
			api.IsZero(api.Add(api.Cmp(y, area.bottomRight.Y), 1)),
		),
	)

	// (inCropAreaX && inCropAreaY)
	inCropArea := api.And(inCropAreaX, inCropAreaY)

	return inCropArea
}
