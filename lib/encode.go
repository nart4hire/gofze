package lib

import (
	"encoding/binary"
	"encoding/hex"
	"math"

	"github.com/nart4hire/fingerprints/lib/types"
)

// Minutiae Data is packed into a Uint32 as follows:
// 2 bits	-> type
// 11 bits	-> X
// 11 bits	-> Y
// 8 bits	-> angle

const BITMASK11 uint32 = 0b11111111111

type minutia struct {
	buffer uint32
}

type Minutia interface {
	Marshal(m *types.Minutiae) uint32
	Unmarshal() *types.Minutiae
	EncodeToHex() string
	GetBuffer() uint32
}

func NewMinutia(min *types.Minutiae) Minutia {
	m := &minutia{}
	m.Marshal(min)
	return m
}

func NewBlankMinutia() Minutia {
	return &minutia{}
}

func (m *minutia) Marshal(min *types.Minutiae) uint32 {
	m.buffer = uint32(min.Type) << 30
	m.buffer |= uint32(min.X) & BITMASK11 << 19
	m.buffer |= uint32(min.Y) & BITMASK11 << 8
	m.buffer |= uint32(math.Round(min.Angle * 128 / math.Pi) - 1) // radians * 180/pi * 256/360
	return m.buffer
}

func (m *minutia) Unmarshal() *types.Minutiae {
	min := types.Minutiae{}
	min.Type = types.MinutiaeType(m.buffer >> 30)
	min.X = int(m.buffer >> 19 & BITMASK11)
	min.Y = int(m.buffer >> 8 & BITMASK11)
	min.Angle = float64(m.buffer & 0xff + 1) * math.Pi / 128
	return &min
}

func (m *minutia) EncodeToHex() string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b[:], m.buffer)
	return hex.EncodeToString(b)
}

func (m *minutia) GetBuffer() uint32 {
	return m.buffer
}