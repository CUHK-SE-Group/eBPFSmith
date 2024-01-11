package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/CUHK-SE-Group/generic-generator/parser"
	"github.com/CUHK-SE-Group/generic-generator/schemas"
	"github.com/CUHK-SE-Group/generic-generator/schemas/query"
	"log/slog"
	"math"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

func GenerateRandomBinaryString(bitLength int) (string, error) {
	if bitLength <= 0 {
		return "", fmt.Errorf("bit length must be positive")
	}

	maxNum := int64(1<<bitLength - 1)
	randomNumber := rand.Int63n(maxNum)

	binaryString := strconv.FormatInt(randomNumber, 2)

	formattedString := fmt.Sprintf("%0*s", bitLength, binaryString)

	return formattedString, nil
}

func BinaryToHex(binaryString string) (string, error) {
	if len(binaryString) != 64 {
		return "", fmt.Errorf("binary string must be 64 bits long, current length: %d", len(binaryString))
	}

	var hexString string
	for i := 0; i < 64; i += 4 {
		segment := binaryString[i : i+4]
		hexDigit, err := strconv.ParseUint(segment, 2, 4)
		if err != nil {
			return "", fmt.Errorf("error parsing binary segment: %s", err)
		}
		hexString += fmt.Sprintf("%X", hexDigit)
	}

	return hexString, nil
}

func BinaryStringToUint64(binaryString string) (uint64, error) {
	if len(binaryString) != 64 {
		return 0, fmt.Errorf("binary string must be 64 bits long, cur: %s", binaryString)
	}

	value, err := strconv.ParseUint(binaryString, 2, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing binary string: %s", err)
	}

	return value, nil
}

type WeightedHandler struct {
}

func (h *WeightedHandler) Handle(chain *schemas.Chain, ctx *schemas.Context, cb schemas.ResponseCallBack) {
	cur := ctx.SymbolStack.Top()
	if len(cur.GetSymbols()) == 0 {
		chain.Next(ctx, cb)
		return
	}
	ctx.SymbolStack.Pop()
	switch ctx.Mode {
	case schemas.ShrinkMode:
		sym := cur.GetSymbols()
		candidates := make([]int, 0)
		repechage := make([]int, 0)
		for i, v := range sym {
			if v.GetDistance() < cur.GetDistance() {
				candidates = append(candidates, i)
			} else {
				repechage = append(repechage, i)
			}
		}
		if len(candidates) == 0 {
			candidates = repechage
		}
		idx := rand.Intn(len(candidates))
		votes := 0
		for i, v := range sym {
			if i != candidates[idx] {
				votes += ctx.VisitedEdge[schemas.GetEdgeID(cur.GetID(), v.GetID())]
			}
		}
		ctx.VisitedEdge[schemas.GetEdgeID(cur.GetID(), sym[candidates[idx]].GetID())]++
		ctx.SymbolStack.Push(sym[candidates[idx]])
		ctx.Result.AddEdge(cur, sym[candidates[idx]])
	default:
		idx := rand.Int() % len(cur.GetSymbols())
		ctx.SymbolStack.Push((cur.GetSymbols())[idx])
		ctx.VisitedEdge[schemas.GetEdgeID(cur.GetID(), (cur.GetSymbols())[idx].GetID())]++
		ctx.Result.AddEdge(cur, (cur.GetSymbols())[idx])
	}

	chain.Next(ctx, cb)
}

func (h *WeightedHandler) HookRoute() []regexp.Regexp {
	return make([]regexp.Regexp, 0)
}

func (h *WeightedHandler) Name() string {
	return "weight"
}

func (h *WeightedHandler) Type() schemas.GrammarType {
	return schemas.GrammarOR
}

type EBPFTermHandler struct {
}

func (h *EBPFTermHandler) isTermPreserve(g *schemas.Node) bool {
	content := g.GetContent()
	return (content[0] == content[len(content)-1]) && ((content[0] == '\'') || content[0] == '"')
}

func (h *EBPFTermHandler) stripQuote(content string) string {
	if content[0] == content[len(content)-1] {
		if (content[0] == '\'') || (content[0] == '"') {
			return content[1 : len(content)-1]
		}
	}
	return content
}

func (h *EBPFTermHandler) Handle(chain *schemas.Chain, ctx *schemas.Context, cb schemas.ResponseCallBack) {
	cur := ctx.SymbolStack.Top()
	ctx.SymbolStack.Pop()
	if len(cur.GetSymbols()) != 0 {
		slog.Error("Pattern mismatched[Terminal]")
		return
	}
	fmt.Println(cur.GetID(), cur.GetContent())
	//if cur.GetID() == "offset#0" {
	//	bits, err := GenerateRandomBinaryString(16)
	//	if err != nil {
	//		panic(err)
	//	}
	//	cur.SetContent(bits)
	//} else if cur.GetID() == "imm#0" {
	//	bits, err := GenerateRandomBinaryString(32)
	//	if err != nil {
	//		panic(err)
	//	}
	//	cur.SetContent(bits)
	//}
	ctx.Result.AddEdge(cur, cur) // 用一个自环标记到达了最后的终结符节点
	chain.Next(ctx, cb)
}

func (h *EBPFTermHandler) HookRoute() []regexp.Regexp {
	return make([]regexp.Regexp, 0)
}

func (h *EBPFTermHandler) Name() string {
	return "ebpfterminalhandler"
}

func (h *EBPFTermHandler) Type() schemas.GrammarType {
	return schemas.GrammarTerminal
}
func hexToBinaryString(hexStr string, bits int) (string, error) {
	// 将十六进制字符串转换为整数
	hexNum, err := strconv.ParseInt(hexStr, 0, 64)
	if err != nil {
		return "", err
	}

	// 格式化为二进制字符串
	formatString := fmt.Sprintf("%%0%db", bits)
	return fmt.Sprintf(formatString, hexNum), nil
}

type MonitorHandler struct {
}

func (h *MonitorHandler) Handle(chain *schemas.Chain, ctx *schemas.Context, cb schemas.ResponseCallBack) {
	if ctx.Constraint == nil {
		chain.Next(ctx, cb)
		return
	}
	cur := ctx.SymbolStack.Top()
	slog.Info("passing", "id", cur.GetID(), "content", cur.GetContent())
	constraints := ctx.Constraint.GetConstraints()
	trace := append(ctx.SymbolStack.ProductionTrace, strings.Split(strings.TrimSpace(cur.GetID()), "#")[0])

	var err error
	for _, v := range constraints {
		if query.MatchPattern(trace, v.FirstNode) {
			switch v.FirstOp.Type {
			case schemas.FUNC:
				ctx, err = v.FirstOp.Func(ctx)
			case schemas.REGEX:

			}
		}
		if query.MatchPattern(trace, v.SecondNode) {
			switch v.SecondOp.Type {
			case schemas.FUNC:
				ctx, err = v.SecondOp.Func(ctx)
			case schemas.REGEX:

			}
		}
		switch {
		case errors.Is(err, schemas.ErrIntercept):
			return
		}
	}
	chain.Next(ctx, cb)
}

func (h *MonitorHandler) HookRoute() []regexp.Regexp {
	return make([]regexp.Regexp, 0)
}

func (h *MonitorHandler) Name() string {
	return "monitor"
}

func (h *MonitorHandler) Type() schemas.GrammarType {
	return math.MaxInt
}

func Generate() []string {
	g, err := parser.Parse("./ebpf.ebnf", "controlFlowGraph")
	if err != nil {
		panic(err)
	}
	g.MergeProduction()
	g.BuildShortestNotation()
	chain, err := schemas.CreateChain("test", &MonitorHandler{}, &schemas.PlusHandler{}, &schemas.CatHandler{}, &schemas.IDHandler{}, &EBPFTermHandler{}, &WeightedHandler{}, &schemas.OrHandler{}, &schemas.RepHandler{}, &schemas.BracketHandler{})
	if err != nil {
		panic(err)
	}
	cons := constraintSetting()
	ctx, err := schemas.NewContext(g, "controlFlowGraph", context.Background(), cons, nil)
	if err != nil {
		panic(err)
	}
	for !ctx.GetFinish() {
		chain.Next(ctx, func(result *schemas.Result) {
			ctx = result.GetCtx()
			ctx.HandlerIndex = 0
		})
	}
	res := ctx.Result.GetResult(func(content string) string {
		if strings.HasPrefix(content, "0x") {
			sp := strings.Split(content, ":")
			if len(sp) != 2 {
				panic(fmt.Errorf("the length should be 2, %s\n", content))
			}
			bits, err := strconv.Atoi(sp[1])
			if err != nil {
				panic(err)
			}
			content, err = hexToBinaryString(sp[0], bits)
			if err != nil {
				panic(err)
			}
		}
		return content
	})
	codes := strings.Split(res, "\\n")
	fmt.Println(codes)
	return codes
}
