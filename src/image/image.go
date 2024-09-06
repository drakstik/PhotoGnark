package image

import (
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
)

const (
	N = 16
)

/*
PhotoProof defines an image I as a matrix NxN and some metadata M, such that I = {NxN, M}.

We define I as a 2D array of RGBPixel, of size N*N, and
a key:value map, where the value can be any data types supported by Gnark.
*/
type I struct {
	Pixels [N][N]RGBPixel // Fixed-sized 2D array.

	M map[string]interface{} // Image metadata.
}

type Z struct {
	Image     I
	PublicKey signature.PublicKey // public digital signature key
}

type RGBPixel struct {
	R uint8
	G uint8
	B uint8
}

func (img *I) SetPixel(x, y int, color RGBPixel) {
	if x >= 0 && x < len(img.Pixels[0]) && y >= 0 && y < len(img.Pixels) {
		img.Pixels[y][x] = color
	}
}

func (img *I) GetPixel(x, y int) RGBPixel {
	if x >= 0 && x < len(img.Pixels[0]) && y >= 0 && y < len(img.Pixels) {
		return img.Pixels[y][x]
	}
	return RGBPixel{} // Return an empty pixel or handle out-of-bounds
}

func NewImage() I {
	return I{
		Pixels: [N][N]RGBPixel{}, // Initialize with a fixed-size array
		M:      make(map[string]interface{}),
	}
}

// Given a secret key, sign this image
func (img *I) Sign(secretKey signature.Signer) []byte {
	// Instantiate hash function to be used when signing the image
	hFunc := hash.MIMC_BN254.New()
	signature, err := secretKey.Sign(img.ToBigEndian(), hFunc)
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
	}
	return signature
}

// Create an all white image, with some metadata.
func AllWhiteImage() I {
	img := NewImage()

	// Set all pixels in the image to white
	for x := 0; x < N; x++ {
		for y := 0; y < N; y++ {
			img.SetPixel(x, y, RGBPixel{R: 255, G: 255, B: 255})
		}
	}

	// Set some metadata
	img.M["Author"] = "John Doe"
	img.M["Location"] = "Austin, TX"
	img.M["Dimensions"] = "12x14"

	return img
}

// Given two points (x0,y0) and (x1,y1) that form a rectangle within the image dimensions,
// black out all pixels outside the formed rectangle.
func (img *I) Crop(x0, y0, x1, y1 int) error {
	// Ensure the crop boundaries are within the image dimensions
	if x0 < 0 || y0 < 0 || x1 >= N || y1 >= N || x0 > x1 || y0 > y1 {
		return fmt.Errorf("invalid crop dimensions")
	}

	// Zero out the pixels outside the crop area
	for y := 0; y < N; y++ {
		for x := 0; x < N; x++ {
			if x < x0 || x > x1 || y < y0 || y > y1 {
				img.SetPixel(x, y, RGBPixel{R: 0, G: 0, B: 0})
			}
		}
	}

	return nil
}

// Return the JSON encoded version of an image as bytes.
func (image I) ToByte() []byte {
	encoded_image, err := json.Marshal(image)
	if err != nil {
		fmt.Println("Error while encoding image: " + err.Error())
		return []byte{}
	}

	return encoded_image
}

// Return the JSON encoded version of an image as a string.
func (image I) ToString() string {
	return string(image.ToByte())
}

// Interprets image bytes as the bytes of a big-endian unsigned integer,
// sets z to that value, and return z value as a big endian slice.
// If this step is skipped, you get this error:
// "runtime error: slice bounds out of range"
// This step is required to define an image into something that Gnark circuits understand.
func (image I) ToBigEndian() []byte {
	// Define the picture as a "z value of a field element (fr.element)" that's converted into a big endian
	img_bytes := image.ToByte() // Encode image into bytes using JSON

	var msgFr fr.Element // Define a field element

	// (https://pkg.go.dev/github.com/consensys/gnark-crypto@v0.9.1/ecc/bn254/fr#Element.SetBytes)
	msgFr.SetBytes(img_bytes)                 // Set the image bytes as the z value for the fr.Element
	big_endian_bytes_Image := msgFr.Marshal() // Convert z value to a big endian slice

	return big_endian_bytes_Image
}
