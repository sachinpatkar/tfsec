package custom

import (
	"fmt"
	"github.com/zclconf/go-cty/cty"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func processFoundChecks(checks ChecksFile) {
	for _, customCheck := range checks.Checks {
		fmt.Printf("Loading check: %s\n", customCheck.Code)
		scanner.RegisterCheck(scanner.Check{
			Code:           customCheck.Code,
			Description:    scanner.RuleDescription(customCheck.Code),
			Provider:       customCheck.Provider,
			RequiredTypes:  customCheck.RequiredTypes,
			RequiredLabels: customCheck.RequiredLabels,
			CheckFunc: func(check *scanner.Check, rootBlock *parser.Block, _ *scanner.Context) []scanner.Result {
				matcher := customCheck.Matcher
				if !processMatcherBlocks(matcher, rootBlock, customCheck) {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Custom check failed for resource %s. %s", rootBlock.Name(), customCheck.ErrorMessage),
							rootBlock.Range(),
							customCheck.Severity,
						),
					}
				}
				return nil
			},
		})
	}
}

func processMatcherBlocks(rootMatcher *Matcher, block *parser.Block, customCheck CustomCheck) (passed bool) {
	subMatcher := rootMatcher.SubMatcher
	switch rootMatcher.Type {
	case Block:
		b := block.GetBlock(rootMatcher.MatchName)
		if b != nil {
			if subMatcher != nil {
				return processMatcherBlocks(subMatcher, b, customCheck)
			}
		} else if customCheck.IsRequired {
			return false

		}
	case Attribute:
		a := block.GetAttribute(rootMatcher.MatchName)
		if a != nil {
			return processAttribute(a, rootMatcher.SubMatcher)
		} else if customCheck.IsRequired {

		}
	}
	return false
}

func processAttribute(attr *parser.Attribute, submatcher *Matcher) (passed bool) {
	switch submatcher.Type {
	case Key:
		valueMap := attr.Value().AsValueMap()
		match := valueMap[submatcher.MatchName]
		return processValueMap(match, submatcher)
	case Item:
		valueSlice := attr.Value()
		processValueSlice(valueSlice, submatcher)
	case Val:
	}
	return false

}

func processValueSlice(match cty.Value, submatcher *Matcher) (passed bool) {
	switch submatcher.CheckAction {
	case IsPresent:
		return match.Type() != cty.NilType
	case IsNotPresent:
		return match.Type() == cty.NilType
	case StartsWith:
		return strings.HasPrefix(match.AsString(), submatcher.MatchName)
	case EndsWith:
		return strings.HasSuffix(match.AsString(), submatcher.MatchName)
	case Contains:
		return strings.Contains(match.AsString(), submatcher.MatchName)
	}
	return false

}

func processValueMap(match cty.Value, submatcher *Matcher) (passed bool) {
	switch submatcher.CheckAction {
	case IsPresent:
		return match.Type() != cty.NilType
	case IsNotPresent:
		return match.Type() == cty.NilType
	case Contains:
		for _, value := range match.AsValueSlice() {
			return value.AsString() == submatcher.MatchValue
		}
	}
	return false
}
