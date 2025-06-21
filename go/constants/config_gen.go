//go:build ignore
// +build ignore

// run : go run config_gen.go -network tiny

package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// ConfigConstants represents a set of constants from a config file
type ConfigConstants struct {
	Network string
	Values  map[string]interface{}
}

// ConstantMapping defines how to map from config name to internal name and type
type ConstantMapping struct {
	InternalName string
	Type         string
	Comment      string
}

// Define mappings from config names to internal names and types
var constantMappings = map[string]ConstantMapping{
	"TotalValidators":             {"NumValidators", "uint16", "V"},
	"TotalCores":                  {"NumCores", "uint16", "C"},
	"TicketEntriesPerValidator":   {"NumTicketEntries", "int", "N"},
	"EpochLength":                 {"NumTimeslotsPerEpoch", "uint32", "E"},
	"TicketSubmissionEndSlot":     {"TicketSubmissionEndingSlotPhaseNumber", "uint32", "Y"},
	"MaxTicketsPerExtrinsic":      {"MaxTicketsPerExtrinsic", "uint16", "K"},
	"MaxAuthorizationQueueItems":  {"AuthorizerQueueLength", "uint16", "Q"},
	"MaxAuthorizationPoolItems":   {"MaxItemsInAuthorizationsPool", "uint16", "O"},
	"ValidatorCoreRotationPeriod": {"ValidatorCoreAssignmentsRotationPeriodInTimeslots", "uint16", "R"},
	"SegmentSize":                 {"SegmentSize", "uint32", "W_G"},
	"ECPieceSize":                 {"ErasureCodedPiecesSize", "uint32", "W_E"},
	"NumECPiecesPerSegment":       {"ErasureCodedPiecesInSegment", "uint32", "W_P"},
	"PreimageExpiryPeriod":        {"UnreferencePreimageExpungeTimeslots", "uint32", "D"},
}

// Additional constants that might not be in the config file
var additionalConstants = map[string]map[string]string{
	"MaxExtrinsicsInWorkPackage":        {"type": "uint16", "value": "128", "comment": "T"},
	"IsAuthorizedCodeMaxSizeOctets":     {"type": "uint32", "value": "64000", "comment": "W_A"},
	"MaxSizeEncodedWorkPackage":         {"type": "uint32", "value": "12 << 20", "comment": "W_B"},
	"ServiceCodeMaxSize":                {"type": "uint32", "value": "4000000", "comment": "W_C"},
	"ServiceMinimumBalance":             {"type": "uint64", "value": "100", "comment": "B_S"},
	"ServiceMinimumBalancePerItem":      {"type": "uint64", "value": "10", "comment": "B_I"},
	"ServiceMinimumBalancePerOctet":     {"type": "uint64", "value": "1", "comment": "B_L"},
	"RecentHistorySizeBlocks":           {"type": "uint16", "value": "8", "comment": "H"},
	"UnavailableWorkTimeoutTimeslots":   {"type": "uint16", "value": "5", "comment": "U"},
	"MaxWorkItemsInPackage":             {"type": "uint16", "value": "16", "comment": "I"},
	"MaxSumDependencyItemsInReport":     {"type": "uint16", "value": "8", "comment": "J"},
	"SingleAccumulationAllocatedGas":    {"type": "uint64", "value": "10000000", "comment": "G_A"},
	"AccumulationQueueMaxEntries":       {"type": "uint16", "value": "1024", "comment": "S"},
	"DynamicAddressAlignmentFactor":     {"type": "int", "value": "2", "comment": "Z_A"},
	"IsAuthorizedGasAllocation":         {"type": "uint64", "value": "50000000", "comment": "G_I"},
	"RefineGasAllocation":               {"type": "uint64", "value": "5000000000", "comment": "G_R"},
	"AllAccumulationTotalGasAllocation": {"type": "uint64", "value": "3500000000", "comment": "G_T"},
	"MaxImportsInWorkPackage":           {"type": "uint32", "value": "3072", "comment": "W_M"},
	"MaxTotalSizeWorkReportBlobs":       {"type": "uint32", "value": "48 << 10", "comment": "W_R"},
	"TransferMemoSize":                  {"type": "uint32", "value": "128", "comment": "W_T"},
	"MaxExportsInWorkPackage":           {"type": "uint32", "value": "3072", "comment": "W_X"},
	"LookupAnchorMaxAgeTimeslots":       {"type": "uint32", "value": "14400", "comment": "L"},
	"SlotPeriodInSeconds":               {"type": "uint16", "value": "6", "comment": "P"},
	"JamCommonEraStartUnixTime":         {"type": "int64", "value": "1735732800", "comment": "JCE epoch (2025-01-01 12:00 UTC)"},
}

func main() {
	// Define command line flags
	networkFlag := flag.String("network", "tiny", "Network to generate constants for (e.g., tiny, full)")
	configPathFlag := flag.String("config-path", "", "Path to the external config file (optional, will be auto-determined if not provided)")
	outputFileFlag := flag.String("output", "constants.go", "Output file path")

	flag.Parse()

	// Auto-determine config path if not provided
	configPath := *configPathFlag
	if configPath == "" {
		// Default path pattern for config files
		configPath = fmt.Sprintf("../../../jamtestnet/chainspecs/configs/config_%s.go", *networkFlag)
		fmt.Printf("Auto-determined config path: %s\n", configPath)
	}

	// Parse the specified config file
	config, err := parseConfigFile(configPath)
	if err != nil {
		fmt.Printf("Error parsing config file %s: %v\n", configPath, err)
		os.Exit(1)
	}

	if config == nil {
		fmt.Printf("Error: Could not extract constants from %s\n", configPath)
		os.Exit(1)
	}

	// Override the network name if specified
	if *networkFlag != "" {
		config.Network = *networkFlag
	}

	// Generate constants.go file
	generateConstantsFile(config, *outputFileFlag)
}

// parseConfigFile parses a Go file containing constants
func parseConfigFile(filePath string) (*ConfigConstants, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	config := &ConfigConstants{
		Network: filepath.Base(filePath),
		Values:  make(map[string]interface{}),
	}

	// Extract constants
	ast.Inspect(node, func(n ast.Node) bool {
		if constDecl, ok := n.(*ast.GenDecl); ok && constDecl.Tok == token.CONST {
			for _, spec := range constDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok {
					for i, name := range valueSpec.Names {
						if name.Name == "Network" {
							// Extract network name
							if basicLit, ok := valueSpec.Values[i].(*ast.BasicLit); ok {
								networkName := strings.Trim(basicLit.Value, "\"")
								config.Network = networkName
							}
						} else if i < len(valueSpec.Values) {
							// Extract constant value
							if basicLit, ok := valueSpec.Values[i].(*ast.BasicLit); ok {
								var value interface{}
								switch basicLit.Kind {
								case token.INT:
									// Parse as integer
									var intVal int
									fmt.Sscanf(basicLit.Value, "%d", &intVal)
									value = intVal
								case token.STRING:
									// Parse as string
									value = strings.Trim(basicLit.Value, "\"")
								}
								config.Values[name.Name] = value
							}
						}
					}
				}
			}
		}
		return true
	})

	return config, nil
}

// generateConstantsFile generates the constants.go file
func generateConstantsFile(config *ConfigConstants, outputFile string) {
	f, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating %s: %v\n", outputFile, err)
		os.Exit(1)
	}
	defer f.Close()

	// Write file header
	fmt.Fprintln(f, "// Code generated by config_gen.go; DO NOT EDIT.")
	fmt.Fprintln(f, "// Generated from network:", config.Network)
	fmt.Fprintln(f, "package constants")
	fmt.Fprintln(f)

	// Write primary constants with proper types
	for configName, value := range config.Values {
		// Skip the Network constant
		if configName == "Network" {
			continue
		}

		// Get the mapping for this constant
		mapping, ok := constantMappings[configName]
		if !ok {
			fmt.Printf("Warning: No mapping found for constant %s, skipping\n", configName)
			continue
		}

		// Format the comment
		comment := ""
		if mapping.Comment != "" {
			comment = " // " + mapping.Comment
		}

		// Write the constant with the proper type
		fmt.Fprintf(f, "const %s %s = %v%s\n\n", mapping.InternalName, mapping.Type, value, comment)
	}

	// Write additional constants that aren't in the config file
	fmt.Fprintln(f, "// Additional constants")
	for name, details := range additionalConstants {
		comment := ""
		if details["comment"] != "" {
			comment = " // " + details["comment"]
		}
		fmt.Fprintf(f, "const %s %s = %s%s\n\n", name, details["type"], details["value"], comment)
	}

	// Write derived constants
	fmt.Fprintln(f, "// Derived constants")
	fmt.Fprintln(f, "const TwoThirdsNumValidators uint16 = 2 * NumValidators / 3")
	fmt.Fprintln(f, "const NumValidatorSafetyThreshold uint16 = TwoThirdsNumValidators + 1")
	fmt.Fprintln(f, "const OneThirdNumValidators uint16 = NumValidators / 3")
}
