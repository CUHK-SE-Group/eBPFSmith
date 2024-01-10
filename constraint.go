package main

import (
	"fmt"
	"github.com/CUHK-SE-Group/generic-generator/schemas"
	"log/slog"
	"math/rand"
)

func generateRandomRegString() string {
	hexDigits := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "d"}
	randomDigit := hexDigits[rand.Intn(len(hexDigits))]
	return fmt.Sprintf("0x%s:4", randomDigit)
}
func constraintSetting() *schemas.ConstraintGraph {
	// default / BPF_K case, the imm field is used.
	immDefaultChoice := schemas.Constraint{
		FirstNode:  "imm",
		SecondNode: "",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				slog.Info("dealing with default / BPF_K case, the imm field is used", "id", ctx.SymbolStack.Top().GetID())
				cur := ctx.SymbolStack.Top()
				ctx.SymbolStack.Pop()
				bits, err := GenerateRandomBinaryString(16)
				if err != nil {
					panic(err)
				}
				cur.SetContent(bits)
				ctx.Result.AddEdge(cur, cur)
				return ctx, nil
			},
		},
	}
	// BPF_X, the imm field should be 0
	immBPFXChoice := schemas.Constraint{
		FirstNode:  "imm",
		SecondNode: "source/BPF_X",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				slog.Info("dealing with BPF_X, the imm field should be 0", "id", ctx.SymbolStack.Top().GetID())
				return ctx, nil
			},
		},
		SecondOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				cur := ctx.SymbolStack.Top()
				ctx.SymbolStack.Pop()
				cur.SetContent("0x0:32")
				ctx.Result.AddEdge(cur, cur)
				return ctx, nil
			},
		},
	}
	// default / BPF_X case, the src field is used.
	srcDefaultChoice := schemas.Constraint{
		FirstNode:  "src",
		SecondNode: "",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				return ctx, nil //pass
			},
		},
	}
	// BPF_K, the src field should be 0
	srcBPFKChoice := schemas.Constraint{
		FirstNode:  "imm",
		SecondNode: "src",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				slog.Info("dealing with BPF_K, the src field should be 0", "id", ctx.SymbolStack.Top().GetID())
				return ctx, nil
			},
		},
		SecondOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				slog.Info("dealing with BPF_K, the src field should be 0 1111", "id", ctx.SymbolStack.Top().GetID())
				cur := ctx.SymbolStack.Top()
				ctx.SymbolStack.Pop()
				cur.SetContent("0x0:4")
				ctx.Result.AddEdge(cur, cur)
				return ctx, nil
			},
		},
	}

	g := schemas.NewConstraintGraph()
	g.AddBinaryConstraint(immDefaultChoice)
	g.AddBinaryConstraint(immBPFXChoice)
	g.AddBinaryConstraint(srcBPFKChoice)
	g.AddBinaryConstraint(srcDefaultChoice)
	return g

}
