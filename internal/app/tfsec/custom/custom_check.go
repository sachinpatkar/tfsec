package custom

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

type MatchType string
type CheckAction string

const (
	Block     MatchType = "block"
	Attribute MatchType = "attribute"
	Key       MatchType = "key"
	Item      MatchType = "item"
	Val       MatchType = "value"

	IsPresent    CheckAction = "isPresent"
	IsNotPresent CheckAction = "isNotPresent"
	StartsWith   CheckAction = "startsWith"
	EndsWith     CheckAction = "endsWith"
	Contains     CheckAction = "contains"
)

type Matcher struct {
	MatchName   string      `json:"matchName"`
	MatchValue  string      `json:"matchValue,omitempty;"`
	CheckAction CheckAction `json:"checkAction"`
	Type        MatchType   `json:"type"`
	SubMatcher  *Matcher    `json:"subMatch,omitempty"`
}

type CustomCheck struct {
	Code           scanner.RuleID          `json:"code"`
	Description    scanner.RuleDescription `json:"description"`
	Provider       scanner.RuleProvider    `json:"provider"`
	RequiredTypes  []string                `json:"requiredTypes"`
	RequiredLabels []string                `json:"requiredLabels"`
	Severity       scanner.Severity        `json:"severity"`
	ErrorMessage   string                  `json:"errorMessage,omitempty"`
	Matcher        *Matcher                `json:"matcher"`
	IsRequired     bool                    `json:"isRequired"`
}
