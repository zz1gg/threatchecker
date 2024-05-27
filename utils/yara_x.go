package utils

/*
#include <stdlib.h>
#include "../include/yara_x.h"
*/
import "C"
import (
	"embed"
	"fmt"
	yara_x "github.com/VirusTotal/yara-x/go"
	"os"
)

//go:embed yara_rules
var f embed.FS

// https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44
// https://github.com/Yara-Rules/rules/blob/master/antidebug_antivm/antidebug_antivm.yar

type ScanResults struct {
	Rule           string
	Namespace      string
	IdentifiedData string
	OffsetValue    uint
	Length         uint
}

// ScanWithYara analyze file with Yara rule
func ScanWithYara(ruleFile string, targetFilebytes []byte) {

	allyararules := LoadRulesFromFile(ruleFile)
	fmt.Printf("\n[+] ScanResults with Yara: \n")
	results2 := YaraScan(allyararules, targetFilebytes)
	for i, r := range results2 {
		fmt.Printf("[+] No.%d\n", i)
		fmt.Println("[+] Matching rules： ", r.Rule)
		fmt.Println("[+] NameSpace： ", r.Namespace)
		red.Printf("[!] Identified matching rules bytes at offset: 0x%d, Length: %d\n", r.OffsetValue, r.Length)
		fmt.Println(r.IdentifiedData)
	}
}

// YaraScan
func YaraScan(rules *yara_x.Rules, targetFilebytes []byte) []ScanResults {
	var results []ScanResults
	var result ScanResults

	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()
	defer rules.Destroy()
	//data, err := os.ReadFile(targetFile)
	if err != nil {
		fmt.Println("[-] Error:", err)
		os.Exit(1)
	}

	//fmt.Printf("[+] Target file size is : %d bytes \n", len(targetFilebytes))

	// Execute scan
	matches, err := scanner.Scan(targetFilebytes)
	if err != nil {
		fmt.Println("[-] Scan failed", err)
		os.Exit(1)
	}

	/*
		for _, match := range matches {
			fmt.Printf("Rule: %s, Namespace: %s\n", match.Identifier(), match.Namespace())
			for _, pattern := range match.Patterns() {
				//fmt.Printf("Pattern: %s\n", pattern.Identifier())
				for _, match := range pattern.Matches() {
					fmt.Printf("[!] Identified end of bad bytes at offset: 0x%d, Length: %d\n", match.Offset(), match.Length())
					printHexFeature(data, match.Offset(), match.Length())
				}
			}
		}

	*/
	//Return matching results
	for _, rmatch := range matches {
		for _, pattern := range rmatch.Patterns() {
			for _, match := range pattern.Matches() {
				result = ScanResults{
					Rule:           rmatch.Identifier(),
					Namespace:      rmatch.Namespace(),
					IdentifiedData: Hexdump(targetFilebytes, match.Offset(), match.Length()),
					OffsetValue:    match.Offset(),
					Length:         match.Length(),
				}
				results = append(results, result)
			}
		}
	}

	return results

}

// LoadRulesFromFile method loads YARA rules from a file and adds them to the scanner
func LoadRulesFromFile(ruleFile string) *yara_x.Rules {

	var rules *yara_x.Rules

	c, _ := yara_x.NewCompiler()
	rule, _ := f.ReadFile("yara_rules/AntiDebugging.yara")

	rule2, _ := f.ReadFile("yara_rules/capabilities.yar")

	err := c.AddSource(string(rule))

	if err != nil {
		fmt.Println("[-] Error Loading Yara Rule1 File with:", err)
		os.Exit(1)
	}
	err = c.AddSource(string(rule2))

	if err != nil {
		fmt.Println("[-] Error Loading Yara Rule2 File with:", err)
		os.Exit(1)
	}

	if ruleFile == "" {
		fmt.Println("[+] Scan With Default Yara Rule File...")
		// Get the compiled rule

		rules = c.Build()
		//fmt.Println(rules)
		return rules

	} else {
		fmt.Println("[+] Scan With Default and Loaded Yara Rule File...")
		// Read Yara File Contents
		rulecontent, err := os.ReadFile(ruleFile)
		if err != nil {
			fmt.Println("[-] Error Reading Yara Rule File with:", err)
			//os.Exit(1)
		}
		// Add YARA rule file contents to the compiler
		err = c.AddSource(string(rulecontent))
		if err != nil {
			fmt.Println("[-] Error Loading Specified Yara Rule File with:", err)
			os.Exit(1)
		}

		rules = c.Build()

	}

	return rules
}
