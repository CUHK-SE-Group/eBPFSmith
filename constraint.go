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
	offsetDefaultChoice := schemas.Constraint{
		FirstNode:  "offset",
		SecondNode: "",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				slog.Info("dealing with default / BPF_K case, the imm field is used", "id", ctx.SymbolStack.Top().GetID())
				cur := ctx.SymbolStack.Top()
				ctx.SymbolStack.Pop()
				if ctx.MemoryExchange["BPF_X_selected"] == 1 || ctx.MemoryExchange["BPF_K_selected"] == 1 { // 和 reg 的操作
					cur.SetContent("0x0:16")
					ctx.Result.AddEdge(cur, cur)
					return ctx, schemas.ErrIntercept
				}

				bits, err := GenerateRandomBinaryString(16)
				if err != nil {
					panic(err)
				}
				cur.SetContent(bits)
				ctx.Result.AddEdge(cur, cur)
				return ctx, schemas.ErrIntercept
			},
		},
	}

	// default / BPF_K case, the imm field is used.
	immDefaultChoice := schemas.Constraint{
		FirstNode:  "imm",
		SecondNode: "",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				if ctx.MemoryExchange["BPF_X_selected"] != 0 {
					return ctx, nil
				}
				slog.Info("dealing with default / BPF_K case, the imm field is used", "id", ctx.SymbolStack.Top().GetID())
				cur := ctx.SymbolStack.Top()
				ctx.SymbolStack.Pop()
				bits, err := GenerateRandomBinaryString(32)
				if err != nil {
					panic(err)
				}
				cur.SetContent(bits)
				ctx.Result.AddEdge(cur, cur)
				return ctx, schemas.ErrIntercept
			},
		},
	}
	// BPF_X, the imm field should be 0
	immBPFXChoice := schemas.Constraint{
		Weight:     10,
		FirstNode:  "source/BPF_X",
		SecondNode: "imm",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				slog.Info("dealing with BPF_X, the imm field should be 0", "id", ctx.SymbolStack.Top().GetID())
				ctx.MemoryExchange["BPF_X_selected"] = 1
				return ctx, nil
			},
		},
		SecondOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				if ctx.MemoryExchange["BPF_X_selected"] != 1 {
					return ctx, nil
				}
				cur := ctx.SymbolStack.Top()
				ctx.SymbolStack.Pop()

				cur.SetContent("0x0:32")
				ctx.Result.AddEdge(cur, cur)
				ctx.MemoryExchange["BPF_X_selected"] = 0
				return ctx, schemas.ErrIntercept
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
		Weight:     10,
		FirstNode:  "source/BPF_K",
		SecondNode: "src",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				slog.Info("dealing with BPF_K, the src field should be 0", "id", ctx.SymbolStack.Top().GetID())
				ctx.MemoryExchange["BPF_K_selected"] = 1
				return ctx, nil
			},
		},
		SecondOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				if ctx.MemoryExchange["BPF_K_selected"] != 1 {
					return ctx, nil
				}
				cur := ctx.SymbolStack.Top()
				ctx.SymbolStack.Pop()
				cur.SetContent("0x0:4")
				ctx.Result.AddEdge(cur, cur)
				ctx.MemoryExchange["BPF_K_selected"] = 0
				return ctx, schemas.ErrIntercept
			},
		},
	}
	LDXDefaultChoice := schemas.Constraint{
		Weight:     11,
		FirstNode:  "BPF_LDX",
		SecondNode: "imm",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				ctx.MemoryExchange["BPF_LDX_selected"] = 1 // LD意味着，imm得是0
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
				ctx.MemoryExchange["BPF_LDX_selected"] = 0
				return ctx, schemas.ErrIntercept
			},
		},
	}
	STXDefaultChoice := schemas.Constraint{
		Weight:     11,
		FirstNode:  "BPF_STX",
		SecondNode: "imm",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				ctx.MemoryExchange["BPF_STX_selected"] = 1 // STX 意味着，imm得是0
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
				ctx.MemoryExchange["BPF_STX_selected"] = 0
				return ctx, schemas.ErrIntercept
			},
		},
	}
	STDefaultChoice := schemas.Constraint{
		Weight:     11,
		FirstNode:  "BPF_ST",
		SecondNode: "src",
		FirstOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				ctx.MemoryExchange["BPF_ST_selected"] = 1 // ST 意味着，src得是0
				return ctx, nil
			},
		},
		SecondOp: schemas.Action{
			Type: schemas.FUNC,
			Func: func(ctx *schemas.Context) (*schemas.Context, error) {
				cur := ctx.SymbolStack.Top()
				ctx.SymbolStack.Pop()

				cur.SetContent("0x0:4")
				ctx.Result.AddEdge(cur, cur)
				ctx.MemoryExchange["BPF_ST_selected"] = 0
				return ctx, schemas.ErrIntercept
			},
		},
	}
	g := schemas.NewConstraintGraph()
	g.AddBinaryConstraint(immDefaultChoice)
	g.AddBinaryConstraint(offsetDefaultChoice)
	g.AddBinaryConstraint(srcDefaultChoice)
	g.AddBinaryConstraint(immBPFXChoice)
	g.AddBinaryConstraint(srcBPFKChoice)
	g.AddBinaryConstraint(LDXDefaultChoice)
	g.AddBinaryConstraint(STXDefaultChoice)
	g.AddBinaryConstraint(STDefaultChoice)
	return g
}
