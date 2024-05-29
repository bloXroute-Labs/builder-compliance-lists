package ofac

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestCheckCompliance(t *testing.T) {
	UpdateComplianceLists(
		ComplianceRegistry{
			"blacklist": {
				common.HexToAddress("0x0"): {},
				common.HexToAddress("0x1"): {},
			},
		},
	)
	if CheckCompliance("blacklist", []common.Address{common.HexToAddress("0x2"), common.HexToAddress("0x0")}) == true {
		t.Error("CheckCompliance failed")
	}
	if CheckCompliance("blacklist", []common.Address{common.HexToAddress("0x2"), common.HexToAddress("0x1")}) == true {
		t.Error("CheckCompliance failed")
	}
	if CheckCompliance("random", []common.Address{common.HexToAddress("0x2"), common.HexToAddress("0x3")}) == false {
		t.Error("CheckCompliance failed")
	}
}

func TestComplianceRegistry_MarshalUnmarshal(t *testing.T) {
	randomComplianceMaps := make([]ComplianceMap, 10)
	for j := 0; j < 10; j++ {
		randomComplianceMaps[j] = make(ComplianceMap)
		for i := 1000 * j; i < 1000*(j+1); i++ {
			randomComplianceMaps[j][common.HexToAddress("0x"+fmt.Sprintf("%040x", i))] = struct{}{}
		}
	}
	veryLongString := strings.Repeat("a", 1000)

	tests := []struct {
		name           string
		complianceList ComplianceRegistry
		expectError    bool
	}{
		{
			name: "Regular list",
			complianceList: ComplianceRegistry{
				"list1": {
					common.HexToAddress("0xABCDEF1234567890ABCDEF1234567890ABCDEF12"): {},
					common.HexToAddress("0x1234567890ABCDEF1234567890ABCDEF12345678"): {},
				},
				"list2": {
					common.HexToAddress("0xFEDCBA0987654321FEDCBA0987654321FEDCBA09"): {},
				},
			},
			expectError: false,
		},
		{
			name:           "Empty list",
			complianceList: make(ComplianceRegistry),
			expectError:    false,
		},
		{
			name:           "Invalid unmarshal",
			complianceList: nil, // This will not be directly used but indicates an invalid case
			expectError:    true,
		},
		{
			name: "Empty compliance map",
			complianceList: ComplianceRegistry{
				"empty": ComplianceMap{},
			},
			expectError: false,
		},
		{
			name: "Empty compliance map with empty name",
			complianceList: ComplianceRegistry{
				"": ComplianceMap{},
			},
			expectError: false,
		},
		{
			name: "Big compliance name with big compliance map",
			complianceList: ComplianceRegistry{
				"big":          randomComplianceMaps[0],
				"another_big":  randomComplianceMaps[1],
				veryLongString: randomComplianceMaps[2],
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Special case for invalid unmarshal test
			if tc.complianceList == nil {
				var unmarshalledList ComplianceRegistry
				err := unmarshalledList.UnmarshalSSZ([]byte{1, 2, 3}) // Assuming this is invalid data
				if (err != nil) != tc.expectError {
					t.Errorf("expected error: %v, got: %v", tc.expectError, err)
				}
				return
			}

			// Proceed with regular marshal and unmarshal tests
			marshaledBytes, err := tc.complianceList.MarshalSSZ()
			if (err != nil) != tc.expectError {
				t.Fatalf("marshal failed: %v", err)
			}

			unmarshalledList := make(ComplianceRegistry)
			err = unmarshalledList.UnmarshalSSZ(marshaledBytes)
			if (err != nil) != tc.expectError {
				t.Fatalf("unmarshal failed: %v", err)
			}

			for name, complianceMap := range tc.complianceList {
				for addr := range complianceMap {
					if _, found := unmarshalledList[name][addr]; !found {
						t.Fatalf("unmarshalled list does not contain address")
					}
				}
				if len(complianceMap) != len(unmarshalledList[name]) {
					t.Fatalf("unmarshalled list does not contain all addresses")
				}
			}
			if len(tc.complianceList) != len(unmarshalledList) {
				t.Fatalf("unmarshalled list does not contain all compliance maps")
			}
		})
	}
}
