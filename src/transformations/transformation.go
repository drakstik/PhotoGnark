package transformations

import "github.com/consensys/gnark/frontend"

const (
	Identity = 0
	Crop     = 1
)

type Transformation struct {
	T      int
	Params map[string]int // [x0, y0, x1, y1]{...}
}

type FrTransformation struct {
	T      frontend.Variable
	Params CropParams
}

func (t Transformation) ToFr() FrTransformation {
	params := CropParams{X0: t.Params["x0"], Y0: t.Params["y0"], X1: t.Params["x1"], Y1: t.Params["y1"]}
	return FrTransformation{T: t.T, Params: params}
}
