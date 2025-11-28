//go:build ignore
// +build ignore

// run : go run config_gen.go -network tiny -build_tag tiny_constants

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
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

var tinyConstants = map[string]map[string]string{
	"NumValidators":                         {"type": "uint16", "value": "6", "comment": "V"},
	"NumCores":                              {"type": "uint16", "value": "2", "comment": "C"},
	"SlotPeriodInSeconds":                   {"type": "uint16", "value": "6", "comment": "P"},
	"NumTimeslotsPerEpoch":                  {"type": "uint32", "value": "12", "comment": "E"},
	"TicketSubmissionEndingSlotPhaseNumber": {"type": "uint32", "value": "10", "comment": "Y"},
	"NumTicketEntries":                      {"type": "uint16", "value": "3", "comment": "N"},
	"MaxTicketsPerExtrinsic":                {"type": "uint16", "value": "3", "comment": "K"},
	"ValidatorCoreAssignmentsRotationPeriodInTimeslots": {"type": "uint16", "value": "4", "comment": "R"},
	"ErasureCodedPiecesInSegment":                       {"type": "uint32", "value": "1026", "comment": "W_P"},
	"ErasureCodedPiecesSize":                            {"type": "uint32", "value": "4", "comment": "W_E"},
	"UnreferencePreimageExpungeTimeslots":               {"type": "uint32", "value": "32", "comment": "D"},
	"AllAccumulationTotalGasAllocation":                 {"type": "uint64", "value": "20000000", "comment": "G_T"},
	"RefineGasAllocation":                               {"type": "uint64", "value": "1000000000", "comment": "G_R"},
	"LookupAnchorMaxAgeTimeslots":                       {"type": "uint32", "value": "24", "comment": "L"},
}

var fullConstants = map[string]map[string]string{
	"NumValidators":                         {"type": "uint16", "value": "1023", "comment": "V"},
	"NumCores":                              {"type": "uint16", "value": "341", "comment": "C"},
	"SlotPeriodInSeconds":                   {"type": "uint16", "value": "6", "comment": "P"},
	"NumTimeslotsPerEpoch":                  {"type": "uint32", "value": "600", "comment": "E"},
	"TicketSubmissionEndingSlotPhaseNumber": {"type": "uint32", "value": "500", "comment": "Y"},
	"NumTicketEntries":                      {"type": "uint16", "value": "2", "comment": "N"},
	"MaxTicketsPerExtrinsic":                {"type": "uint16", "value": "16", "comment": "K"},
	"ValidatorCoreAssignmentsRotationPeriodInTimeslots": {"type": "uint16", "value": "10", "comment": "R"},
	"ErasureCodedPiecesInSegment":                       {"type": "uint32", "value": "6", "comment": "W_P"},
	"ErasureCodedPiecesSize":                            {"type": "uint32", "value": "684", "comment": "W_E"},
	"UnreferencePreimageExpungeTimeslots":               {"type": "uint32", "value": "19200", "comment": "D"},
	"AllAccumulationTotalGasAllocation":                 {"type": "uint64", "value": "3500000000", "comment": "G_T"},
	"RefineGasAllocation":                               {"type": "uint64", "value": "5000000000", "comment": "G_R"},
	"LookupAnchorMaxAgeTimeslots":                       {"type": "uint32", "value": "14400", "comment": "L"},
}

// Additional constants that might not be in the config file
var additionalConstants = map[string]map[string]string{
	"MaxExtrinsicsInWorkPackage":      {"type": "uint16", "value": "128", "comment": "T"},
	"IsAuthorizedCodeMaxSizeOctets":   {"type": "uint32", "value": "64000", "comment": "W_A"},
	"MaxSizeEncodedWorkPackage":       {"type": "uint32", "value": "13791360", "comment": "W_B"},
	"ServiceCodeMaxSize":              {"type": "uint32", "value": "4000000", "comment": "W_C"},
	"ServiceMinimumBalance":           {"type": "uint64", "value": "100", "comment": "B_S"},
	"ServiceMinimumBalancePerItem":    {"type": "uint64", "value": "10", "comment": "B_I"},
	"ServiceMinimumBalancePerOctet":   {"type": "uint64", "value": "1", "comment": "B_L"},
	"RecentHistorySizeBlocks":         {"type": "uint16", "value": "8", "comment": "H"},
	"UnavailableWorkTimeoutTimeslots": {"type": "uint16", "value": "5", "comment": "U"},
	"MaxWorkItemsInPackage":           {"type": "uint16", "value": "16", "comment": "I"},
	"MaxSumDependencyItemsInReport":   {"type": "uint16", "value": "8", "comment": "J"},
	"SingleAccumulationAllocatedGas":  {"type": "uint64", "value": "10000000", "comment": "G_A"},
	"DynamicAddressAlignmentFactor":   {"type": "int", "value": "2", "comment": "Z_A"},
	"IsAuthorizedGasAllocation":       {"type": "uint64", "value": "50000000", "comment": "G_I"},
	"MaxImportsInWorkPackage":         {"type": "uint32", "value": "3072", "comment": "W_M"},
	"MaxTotalSizeWorkReportBlobs":     {"type": "uint32", "value": "48 << 10", "comment": "W_R"},
	"TransferMemoSize":                {"type": "uint32", "value": "128", "comment": "W_T"},
	"MaxExportsInWorkPackage":         {"type": "uint32", "value": "3072", "comment": "W_X"},
	"JamCommonEraStartUnixTime":       {"type": "int64", "value": "1735732800", "comment": "JCE epoch (2025-01-01 12:00 UTC)"},
	"AuthorizerQueueLength":           {"type": "uint16", "value": "80", "comment": "Q"},
	"MinPublicServiceIndex":           {"type": "uint64", "value": "1 << 16", "comment": "S"},
	"MaxItemsInAuthorizationsPool":    {"type": "uint16", "value": "8", "comment": "O"},
}

func main() {
	// Define command line flags
	networkFlag := flag.String("network", "tiny", "Network to generate constants for (e.g., tiny, full)")
	outputFileFlag := flag.String("output", "constants.go", "Output file path")

	flag.Parse()

	generateConstantsFile(*networkFlag, *outputFileFlag)
}

// generateConstantsFile generates the constants.go file
func generateConstantsFile(network string, outputFile string) {
	f, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating %s: %v\n", outputFile, err)
		os.Exit(1)
	}
	defer f.Close()

	// Write file header
	fmt.Fprintln(f, "// Code generated by config_gen.go; DO NOT EDIT.")
	fmt.Fprintln(f, "// Generated from network:", network)
	fmt.Fprintln(f, "package constants")
	fmt.Fprintln(f)

	// Select network constants based on the network parameter
	var networkConstants map[string]map[string]string
	if network == "full" {
		networkConstants = fullConstants
	} else {
		// Default to tiny constants
		networkConstants = tinyConstants
	}

	// Write config constants
	fmt.Fprintln(f, "// Config constants")

	// Sort keys for deterministic output
	var names []string
	for name := range networkConstants {
		names = append(names, name)
	}
	sort.Strings(names)

	// Write constants in sorted order
	for _, name := range names {
		details := networkConstants[name]
		comment := ""
		if details["comment"] != "" {
			comment = " // " + details["comment"]
		}
		fmt.Fprintf(f, "const %s %s = %s%s\n\n", name, details["type"], details["value"], comment)
	}

	// Write additional constants that aren't in the config file
	fmt.Fprintln(f, "// Additional constants")

	// Sort keys for additional constants
	var additionalNames []string
	for name := range additionalConstants {
		additionalNames = append(additionalNames, name)
	}
	sort.Strings(additionalNames)

	// Write additional constants in sorted order
	for _, name := range additionalNames {
		details := additionalConstants[name]
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
	fmt.Fprintln(f, "const SegmentSize uint32 = ErasureCodedPiecesSize * ErasureCodedPiecesInSegment")
	fmt.Fprintln(f, "const RecoveryThreshold uint32 = ErasureCodedPiecesSize / 2")
}
