package ofac

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	ssz "github.com/ferranbt/fastssz"
)

type ComplianceMap map[common.Address]struct{}

const (
	LengthSizeOffset = 8
	AddressSize      = 20
)

func (complianceMap *ComplianceMap) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(complianceMap)
}

func (complianceMap *ComplianceMap) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	for addr := range *complianceMap {
		dst = append(dst, addr.Bytes()[:]...)
	}
	return dst, nil
}

func (complianceMap *ComplianceMap) UnmarshalSSZ(buf []byte) error {
	numAddresses := len(buf) / AddressSize
	for i := 0; i < numAddresses; i++ {
		(*complianceMap)[common.BytesToAddress(buf[i*AddressSize:(i+1)*AddressSize])] = struct{}{}
	}
	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the SubmitBlockRequest object
func (complianceMap *ComplianceMap) SizeSSZ() (size int) {
	size = len(*complianceMap) * AddressSize
	return size
}

type ComplianceRegistry map[string]ComplianceMap

func (complianceList *ComplianceRegistry) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(complianceList)
}

// SizeSSZ returns the ssz encoded size in bytes for the SubmitBlockRequest object
func (complianceList *ComplianceRegistry) SizeSSZ() (size int) {
	size = LengthSizeOffset // 8 for length of map
	for name, complianceMap := range *complianceList {
		size += len(name) + LengthSizeOffset // 8 for length of name, len(name) for name itself
		size += LengthSizeOffset
		size += complianceMap.SizeSSZ()
	}
	return size
}
func (complianceList *ComplianceRegistry) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	dst = ssz.MarshalUint64(dst, uint64(len(*complianceList)))
	for name, complianceMap := range *complianceList {
		dst = ssz.MarshalUint64(dst, uint64(len(name)))
		dst = append(dst, []byte(name)...)
		if len(name) != len([]byte(name)) {
			return nil, fmt.Errorf("failed to marshal name")
		}
		dst = ssz.MarshalUint64(dst, uint64(complianceMap.SizeSSZ()))
		dst, err = complianceMap.MarshalSSZTo(dst)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func (complianceList *ComplianceRegistry) UnmarshalSSZ(buf []byte) error {
	if complianceList == nil {
		return fmt.Errorf("nil ComplianceRegistry")
	}
	if len(buf) < LengthSizeOffset {
		return fmt.Errorf("buffer too short to unmarshal ComplianceRegistry: expected at least 8 bytes, got %d", len(buf))
	}
	offset := uint64(0)
	numNames := ssz.UnmarshallUint64(buf[offset : offset+LengthSizeOffset])
	offset += LengthSizeOffset
	if len(buf) < int(offset) {
		return fmt.Errorf("buffer too short to contain %d names", numNames)
	}

	for i := uint64(0); i < numNames; i++ {
		if len(buf) < int(offset+LengthSizeOffset) {
			return fmt.Errorf("buffer too short to read name length at index %d", i)
		}
		nameLen := ssz.UnmarshallUint64(buf[offset : offset+LengthSizeOffset])
		offset += LengthSizeOffset
		if len(buf) < int(offset+nameLen) {
			return fmt.Errorf("buffer too short for name %d", i)
		}
		name := string(buf[offset : offset+nameLen])
		offset += nameLen
		if len(name) != int(nameLen) {
			return fmt.Errorf("failed to unmarshal name")
		}
		if len(buf) < int(offset+LengthSizeOffset) {
			return fmt.Errorf("buffer too short for name %s", name)
		}

		complianceMapSize := ssz.UnmarshallUint64(buf[offset : offset+LengthSizeOffset])
		offset += LengthSizeOffset

		complianceMap := make(ComplianceMap)
		if len(buf) < int(offset+complianceMapSize) {
			return fmt.Errorf("buffer too short for complianceMap %s", name)
		}
		err := complianceMap.UnmarshalSSZ(buf[offset : offset+complianceMapSize])
		if err != nil {
			return err
		}
		offset += uint64(complianceMap.SizeSSZ())
		(*complianceList)[name] = complianceMap
	}
	return nil
}
