package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// InstructionState represents a single execution step
type InstructionState struct {
	InstructionCode int
	InstructionName string
	Step            int
	PC              int
	Gas             int
	Registers       []uint64
}

// ParseTestLogFormat parses the test.txt format
func ParseTestLogFormat(filename string) ([]InstructionState, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var states []InstructionState

	stepCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse instruction name, step, pc, gas, and registers
		parts := strings.Fields(line)
		if len(parts) < 7 { // Need at least instruction, step:, value, pc:, value, g:, value
			fmt.Printf("Not enough parts in line: %s\n", line)
			continue
		}

		instName := parts[0]

		// Debug - print the parts
		// fmt.Printf("Line parts: %v\n", parts)

		// We need a more robust approach to extract values that handles variable spacing
		// First, find the indices where each section starts
		stepIdx, pcIdx, gasIdx, regIdx := -1, -1, -1, -1

		for i, part := range parts {
			if strings.HasPrefix(part, "step:") {
				stepIdx = i
			} else if strings.HasPrefix(part, "pc:") {
				pcIdx = i
			} else if strings.HasPrefix(part, "g:") {
				gasIdx = i
			} else if strings.HasPrefix(part, "Registers:") {
				regIdx = i
				break
			}
		}

		if stepIdx == -1 || pcIdx == -1 || gasIdx == -1 || regIdx == -1 {
			// fmt.Printf("Missing required section in line: %s\n", line)
			continue
		}

		// Parse step value - it's between stepIdx and pcIdx
		stepValue := strings.Join(parts[stepIdx+1:pcIdx], "")
		stepValue = strings.TrimSpace(stepValue)
		step, err := strconv.Atoi(stepValue)
		if err != nil {
			fmt.Printf("Error parsing step: %v (value: '%s')\n", err, stepValue)
			continue
		}

		// Parse PC value - it's between pcIdx and gasIdx
		pcValue := strings.Join(parts[pcIdx+1:gasIdx], "")
		pcValue = strings.TrimSpace(pcValue)
		pc, err := strconv.Atoi(pcValue)
		if err != nil {
			fmt.Printf("Error parsing PC: %v (value: '%s')\n", err, pcValue)
			continue
		}

		// Parse Gas value - it's between gasIdx and regIdx
		gasValue := strings.TrimPrefix(parts[gasIdx], "g:")
		if gasIdx+1 < regIdx {
			// There are spaces in the gas value, join them
			gasValue = strings.Join(append([]string{gasValue}, parts[gasIdx+1:regIdx]...), "")
		}
		gasValue = strings.TrimSpace(gasValue)
		gas, err := strconv.Atoi(gasValue)
		if err != nil {
			fmt.Printf("Error parsing gas: %v (value: '%s')\n", err, gasValue)
			continue
		}

		// Parse Registers
		regStr := strings.Join(parts[regIdx:], " ")
		regStr = strings.TrimPrefix(regStr, "Registers:[")
		regStr = strings.TrimSuffix(regStr, "]")
		regParts := strings.Split(regStr, ",")

		registers := make([]uint64, 0, len(regParts))
		for _, r := range regParts {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			reg, err := strconv.ParseUint(r, 10, 64)
			if err != nil {
				continue
			}
			registers = append(registers, reg)
		}

		// Create state
		state := InstructionState{
			InstructionName: instName,
			Step:            step,
			PC:              pc,
			Gas:             gas,
			Registers:       registers,
		}
		states = append(states, state)
		stepCount++
	}

	return states, nil
}

// ParsePVMLogFormat parses the pvm_execution.log format
func ParsePVMLogFormat(filename string) ([]InstructionState, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var states []InstructionState

	stepCount := 0
	re := regexp.MustCompile(`instruction=(\d+) pc=(\d+) g=(\d+) Registers=\[([\d\s]+)\]`)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "SingleStep: instruction=") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) < 5 {
			continue
		}

		// Parse instruction
		instCode, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}

		// Parse PC
		pc, err := strconv.Atoi(matches[2])
		if err != nil {
			continue
		}

		// Parse Gas
		gas, err := strconv.Atoi(matches[3])
		if err != nil {
			continue
		}

		// Parse Registers
		regStr := matches[4]
		regParts := strings.Fields(regStr)

		registers := make([]uint64, 0, len(regParts))
		for _, r := range regParts {
			if r == "" {
				continue
			}
			reg, err := strconv.ParseUint(r, 10, 64)
			if err != nil {
				continue
			}
			registers = append(registers, reg)
		}

		// Create state
		state := InstructionState{
			InstructionCode: instCode,
			Step:            stepCount,
			PC:              pc,
			Gas:             gas,
			Registers:       registers,
		}
		states = append(states, state)
		stepCount++
	}

	return states, nil
}

// ParseTest2LogFormat parses the test2.txt format
func ParseTest2LogFormat(filename string) ([]InstructionState, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var states []InstructionState

	stepCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse the Java log format: timestamp [thread] LEVEL class -- instruction step pc Registers:[values]
		// Example: 14:21:07.238 [main] INFO  io.javajam.pvm.PolkaVM -- JUMP 0 27543 Registers:[4294901760, 4278059008, 0, 0, 0, 0, 0, 4278124544, 147, 0, 0, 0, 0]

		// Check if line contains PolkaVM information
		if !strings.Contains(line, "INFO  io.javajam.pvm.PolkaVM --") {
			continue
		}

		// Split at the double dash delimiter to get the actual instruction part
		parts := strings.Split(line, "--")
		if len(parts) != 2 {
			continue
		}

		instructionPart := strings.TrimSpace(parts[1])
		instructionParts := strings.Fields(instructionPart)

		// Need at least instruction name, step, PC, and Registers section
		if len(instructionParts) < 4 {
			fmt.Printf("Not enough parts in instruction: %s\n", instructionPart)
			continue
		}

		// Parse instruction name
		instName := instructionParts[0]

		// Parse step number
		step, err := strconv.Atoi(instructionParts[1])
		if err != nil {
			fmt.Printf("Error parsing step: %v (value: '%s')\n", err, instructionParts[1])
			continue
		}

		// Parse PC value
		pc, err := strconv.Atoi(instructionParts[2])
		if err != nil {
			fmt.Printf("Error parsing PC: %v (value: '%s')\n", err, instructionParts[2])
			continue
		}

		// Find the Registers section and parse it
		var registersStr string
		for i := 3; i < len(instructionParts); i++ {
			if strings.HasPrefix(instructionParts[i], "Registers:") {
				registersStr = strings.Join(instructionParts[i:], " ")
				break
			}
		}

		if registersStr == "" {
			fmt.Printf("No Registers section found in line: %s\n", line)
			continue
		}

		// Parse the registers
		registersStr = strings.TrimPrefix(registersStr, "Registers:[")
		registersStr = strings.TrimSuffix(registersStr, "]")
		regParts := strings.Split(registersStr, ",")

		registers := make([]uint64, 0, len(regParts))
		for _, r := range regParts {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			reg, err := strconv.ParseUint(r, 10, 64)
			if err != nil {
				fmt.Printf("Error parsing register: %v (value: '%s')\n", err, r)
				continue
			}
			registers = append(registers, reg)
		}

		// Create state - note that we don't have gas information in this format
		// so we'll set it to 0 for now
		state := InstructionState{
			InstructionName: instName,
			Step:            step,
			PC:              pc,
			Gas:             0, // No gas information in this format
			Registers:       registers,
		}
		states = append(states, state)
		stepCount++
	}

	return states, nil
}

// CompareLogs compares two log files
func CompareLogs(testFile, pvmFile string) error {
	testStates, err := ParseTestLogFormat(testFile)
	if err != nil {
		return fmt.Errorf("error parsing test file: %v", err)
	}

	pvmStates, err := ParsePVMLogFormat(pvmFile)
	if err != nil {
		return fmt.Errorf("error parsing PVM file: %v", err)
	}

	// Print summary
	fmt.Printf("Parsed %d states from test file\n", len(testStates))
	fmt.Printf("Parsed %d states from PVM file\n", len(pvmStates))

	// Compare states
	minLen := len(testStates)
	if len(pvmStates) < minLen {
		minLen = len(pvmStates)
	}

	foundMismatch := false

	for i := 0; i < minLen; i++ {
		if foundMismatch {
			break // Stop after first mismatch is found
		}

		testState := testStates[i]
		pvmState := pvmStates[i]

		// Compare PC
		if testState.PC != pvmState.PC {
			fmt.Printf("First mismatch at step %d: PC mismatch - Test: %d, PVM: %d\n", i, testState.PC, pvmState.PC)
			fmt.Printf("Test instruction: %s, PVM instruction code: %d\n", testState.InstructionName, pvmState.InstructionCode)
			foundMismatch = true
			break
		}

		// Compare Gas
		if testState.Gas+9900000 != pvmState.Gas {
			fmt.Printf("First mismatch at step %d: Gas mismatch - Test: %d, PVM: %d\n", i, testState.Gas, pvmState.Gas)
			fmt.Printf("Test instruction: %s, PVM instruction code: %d\n", testState.InstructionName, pvmState.InstructionCode)
			foundMismatch = true
			break
		}

		// Compare Register Length
		// if len(testState.Registers) != len(pvmState.Registers) {
		// 	fmt.Printf("First mismatch at step %d: Register length mismatch - Test: %d, PVM: %d\n",
		// 		i, len(testState.Registers), len(pvmState.Registers))
		// 	fmt.Printf("Test instruction: %s, PVM instruction code: %d\n", testState.InstructionName, pvmState.InstructionCode)
		// 	foundMismatch = true
		// 	break
		// }

		// Compare Register Values
		// for j, reg := range testState.Registers {
		// 	if j >= len(pvmState.Registers) {
		// 		break
		// 	}
		// 	if reg != pvmState.Registers[j] && i > 1500 {
		// 		fmt.Printf("First mismatch at step %d: Register %d mismatch - Test: %d, PVM: %d\n",
		// 			i, j, reg, pvmState.Registers[j])
		// 		fmt.Printf("Test instruction: %s, PVM instruction code: %d\n", testState.InstructionName, pvmState.InstructionCode)
		// 		foundMismatch = true
		// 		break
		// 	}
		// }
	}

	if !foundMismatch {
		if len(testStates) != len(pvmStates) {
			fmt.Printf("No value mismatches found, but number of steps differs - Test: %d, PVM: %d\n",
				len(testStates), len(pvmStates))
		} else {
			fmt.Println("No mismatches found! Logs match completely.")
		}
	}

	return nil
}

// CompareAndCreateMapping compares logs and also creates a mapping from instruction codes to names
func CompareAndCreateMapping(testFile, pvmFile string) error {
	testStates, err := ParseTestLogFormat(testFile)
	if err != nil {
		return fmt.Errorf("error parsing test file: %v", err)
	}

	pvmStates, err := ParsePVMLogFormat(pvmFile)
	if err != nil {
		return fmt.Errorf("error parsing PVM file: %v", err)
	}

	// Create instruction code to name mapping
	instMapping := make(map[int]string)
	minLen := len(testStates)
	if len(pvmStates) < minLen {
		minLen = len(pvmStates)
	}

	for i := 0; i < minLen; i++ {
		testState := testStates[i]
		pvmState := pvmStates[i]

		if testState.PC == pvmState.PC && testState.Gas == pvmState.Gas {
			instMapping[pvmState.InstructionCode] = testState.InstructionName
		}
	}

	// Print instruction mapping
	fmt.Println("Instruction Code to Name Mapping:")
	for code, name := range instMapping {
		fmt.Printf("%d -> %s\n", code, name)
	}

	return nil
}

// CompareTest2Logs compares test2.txt format with PVM logs
func CompareTest2Logs(testFile, pvmFile string) error {
	testStates, err := ParseTest2LogFormat(testFile)
	if err != nil {
		return fmt.Errorf("error parsing test file: %v", err)
	}

	pvmStates, err := ParsePVMLogFormat(pvmFile)
	if err != nil {
		return fmt.Errorf("error parsing PVM file: %v", err)
	}

	// Print summary
	fmt.Printf("Parsed %d states from test file\n", len(testStates))
	fmt.Printf("Parsed %d states from PVM file\n", len(pvmStates))

	// Compare states
	minLen := len(testStates)
	if len(pvmStates) < minLen {
		minLen = len(pvmStates)
	}

	foundMismatch := false

	for i := 0; i < minLen; i++ {
		if foundMismatch {
			break // Stop after first mismatch is found
		}

		testState := testStates[i]
		pvmState := pvmStates[i]

		// Compare PC
		if testState.PC != pvmState.PC {
			fmt.Printf("First mismatch at step %d: PC mismatch - Test: %d, PVM: %d\n", i, testState.PC, pvmState.PC)
			fmt.Printf("Test instruction: %s, PVM instruction code: %d\n", testState.InstructionName, pvmState.InstructionCode)
			foundMismatch = true
			break
		}

		if pvmState.InstructionCode == 10 {
			continue
		}

		// Skip gas comparison since we don't have gas info in this format
		// Compare Register Length
		if len(testState.Registers) != len(pvmState.Registers) {
			fmt.Printf("First mismatch at step %d: Register length mismatch - Test: %d, PVM: %d\n",
				i, len(testState.Registers), len(pvmState.Registers))
			fmt.Printf("Test instruction: %s, PVM instruction code: %d\n", testState.InstructionName, pvmState.InstructionCode)
			foundMismatch = true
			break
		}

		// Compare Register Values
		for j, reg := range testState.Registers {
			if j >= len(pvmState.Registers) {
				break
			}
			if reg != pvmState.Registers[j] {
				fmt.Printf("First mismatch at step %d: Register %d mismatch - Test: %d, PVM: %d\n",
					i, j, reg, pvmState.Registers[j])
				fmt.Printf("Test instruction: %s, PVM instruction code: %d\n", testState.InstructionName, pvmState.InstructionCode)
				foundMismatch = true
				break
			}
		}
	}

	if !foundMismatch {
		if len(testStates) != len(pvmStates) {
			fmt.Printf("No value mismatches found, but number of steps differs - Test: %d, PVM: %d\n",
				len(testStates), len(pvmStates))
		} else {
			fmt.Println("No mismatches found! Logs match completely.")
		}
	}

	return nil
}

// CompareAndCreateMapping2 compares logs and creates mapping for test2.txt format
func CompareAndCreateMapping2(testFile, pvmFile string) error {
	testStates, err := ParseTest2LogFormat(testFile)
	if err != nil {
		return fmt.Errorf("error parsing test file: %v", err)
	}

	pvmStates, err := ParsePVMLogFormat(pvmFile)
	if err != nil {
		return fmt.Errorf("error parsing PVM file: %v", err)
	}

	// Create instruction code to name mapping
	instMapping := make(map[int]string)
	minLen := len(testStates)
	if len(pvmStates) < minLen {
		minLen = len(pvmStates)
	}

	for i := 0; i < minLen; i++ {
		testState := testStates[i]
		pvmState := pvmStates[i]

		if testState.PC == pvmState.PC && testState.Gas == pvmState.Gas {
			instMapping[pvmState.InstructionCode] = testState.InstructionName
		}
	}

	// Print instruction mapping
	fmt.Println("Instruction Code to Name Mapping:")
	for code, name := range instMapping {
		fmt.Printf("%d -> %s\n", code, name)
	}

	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: log_compare <test_file> <pvm_file>")
		os.Exit(1)
	}

	testFile := os.Args[1]
	pvmFile := os.Args[2]

	// Determine if we're using test2.txt format based on filename
	isTest2Format := strings.Contains(testFile, "test2.txt")

	var err error
	if isTest2Format {
		err = CompareTest2Logs(testFile, pvmFile)
	} else {
		err = CompareLogs(testFile, pvmFile)
	}

	if err != nil {
		fmt.Printf("Error comparing logs: %v\n", err)
		os.Exit(1)
	}

	if isTest2Format {
		err = CompareAndCreateMapping2(testFile, pvmFile)
	} else {
		err = CompareAndCreateMapping(testFile, pvmFile)
	}

	if err != nil {
		fmt.Printf("Error creating mapping: %v\n", err)
		os.Exit(1)
	}
}
