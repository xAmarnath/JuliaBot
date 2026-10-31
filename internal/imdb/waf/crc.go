package waf

import "fmt"

const ieeePolynomial uint32 = 0xEDB88320

var crcTable = buildCRCTable()

func buildCRCTable() [256]uint32 {
	var table [256]uint32
	for i := range 256 {
		v := uint32(i)
		for range 8 {
			if v&1 == 1 {
				v = (v >> 1) ^ ieeePolynomial
			} else {
				v >>= 1
			}
		}
		table[i] = v
	}
	return table
}

func calculateCRC(data string) int64 {
	v := uint32(0xFFFFFFFF)
	for _, r := range data {
		idx := (v ^ uint32(r)) & 0xFF
		v = (v >> 8) ^ crcTable[idx]
	}
	result := 0xFFFFFFFF ^ v
	if result >= 0x80000000 {
		return int64(result) - 0x100000000
	}
	return int64(result)
}

func encodeNumber(n int64) string {
	u := uint32(n & 0xFFFFFFFF)
	return fmt.Sprintf("%08X", u)
}
