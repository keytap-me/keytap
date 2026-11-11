package main

// A small QR code encoder (byte mode, error correction level L, versions 1–20), so `pair` can show its
// link as a code the iPhone's camera scans — no copy and paste. Standard library only, like the rest of
// the bridge. Follows ISO/IEC 18004; the layout arithmetic is the well-known one from Project Nayuki's
// reference implementation (MIT).

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// error correction level L: codewords per block and number of blocks, by version (index 0 unused)
var (
	qrECCPerBlock = [...]int{0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28}
	qrBlocks      = [...]int{0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8}
)

const qrMaxVersion = len(qrBlocks) - 1

type qrCode struct {
	size   int
	dark   [][]bool
	fixed  [][]bool // function modules: not data, not masked
	rawLen int
}

// qrRawCodewords is the number of 8-bit codewords (data + error correction) a version holds.
func qrRawCodewords(ver int) int {
	n := (16*ver+128)*ver + 64
	if ver >= 2 {
		a := ver/7 + 2
		n -= (25*a-10)*a - 55
		if ver >= 7 {
			n -= 36
		}
	}
	return n / 8
}

func qrDataCodewords(ver int) int { return qrRawCodewords(ver) - qrECCPerBlock[ver]*qrBlocks[ver] }

// qrEncode returns the modules of the smallest code that holds text; true is dark.
func qrEncode(text string) ([][]bool, error) {
	data := []byte(text)
	ver, countBits := 0, 8
	for v := 1; v <= qrMaxVersion; v++ {
		cb := 8
		if v >= 10 {
			cb = 16
		}
		if 4+cb+8*len(data) <= 8*qrDataCodewords(v) {
			ver, countBits = v, cb
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("too long for a QR code")
	}

	// the bit stream: mode 0100 (bytes), the length, the bytes, terminator, padding
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, v>>i&1 == 1)
		}
	}
	put(4, 4)
	put(len(data), countBits)
	for _, b := range data {
		put(int(b), 8)
	}
	capBits := 8 * qrDataCodewords(ver)
	put(0, min(4, capBits-len(bits)))
	put(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	codewords := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			codewords[i/8] |= 0x80 >> (i % 8)
		}
	}

	q := &qrCode{size: ver*4 + 17, rawLen: qrRawCodewords(ver)}
	q.dark, q.fixed = make([][]bool, q.size), make([][]bool, q.size)
	for i := range q.dark {
		q.dark[i], q.fixed[i] = make([]bool, q.size), make([]bool, q.size)
	}
	q.drawFunctionPatterns(ver)
	q.drawCodewords(qrInterleave(codewords, ver))

	// the mask with the lowest penalty
	best, bestScore := 0, -1
	for m := 0; m < 8; m++ {
		q.mask(m)
		q.drawFormat(m)
		if s := q.penalty(); bestScore < 0 || s < bestScore {
			best, bestScore = m, s
		}
		q.mask(m) // undo (XOR)
	}
	q.mask(best)
	q.drawFormat(best)
	return q.dark, nil
}

func (q *qrCode) set(x, y int, dark bool) {
	q.dark[y][x] = dark
	q.fixed[y][x] = true
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func (q *qrCode) drawFunctionPatterns(ver int) {
	n := q.size
	for i := 0; i < n; i++ { // timing
		q.set(6, i, i%2 == 0)
		q.set(i, 6, i%2 == 0)
	}
	for _, c := range [][2]int{{3, 3}, {n - 4, 3}, {3, n - 4}} { // finders with their separators
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := c[0]+dx, c[1]+dy
				if x >= 0 && x < n && y >= 0 && y < n {
					d := max(abs(dx), abs(dy))
					q.set(x, y, d != 2 && d != 4)
				}
			}
		}
	}
	if ver >= 2 { // alignment patterns
		num := ver/7 + 2
		step := (ver*4 + num*2 + 1) / (num*2 - 2) * 2
		pos := make([]int, num)
		pos[0] = 6
		for i, p := num-1, n-7; i >= 1; i, p = i-1, p-step {
			pos[i] = p
		}
		for i, cy := range pos {
			for j, cx := range pos {
				if (i == 0 && j == 0) || (i == 0 && j == num-1) || (i == num-1 && j == 0) {
					continue // a finder is there
				}
				for dy := -2; dy <= 2; dy++ {
					for dx := -2; dx <= 2; dx++ {
						q.set(cx+dx, cy+dy, max(abs(dx), abs(dy)) != 1)
					}
				}
			}
		}
	}
	q.drawFormat(0) // reserves the format modules
	if ver >= 7 {   // version information
		rem := ver
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		v := ver<<12 | rem
		for i := 0; i < 18; i++ {
			bit := v>>i&1 == 1
			a, b := n-11+i%3, i/3
			q.set(a, b, bit)
			q.set(b, a, bit)
		}
	}
}

// drawFormat writes the 15 format bits (level L + mask) in both places.
func (q *qrCode) drawFormat(mask int) {
	data := 1<<3 | mask // level L is 01
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	v := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return v>>i&1 == 1 }
	n := q.size
	for i := 0; i <= 5; i++ {
		q.set(8, i, bit(i))
	}
	q.set(8, 7, bit(6))
	q.set(8, 8, bit(7))
	q.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		q.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.set(8, n-15+i, bit(i))
	}
	q.set(8, n-8, true)
}

// qrInterleave splits the data into blocks, adds each block's Reed–Solomon codewords and interleaves them.
func qrInterleave(data []byte, ver int) []byte {
	numBlocks, eccLen, raw := qrBlocks[ver], qrECCPerBlock[ver], qrRawCodewords(ver)
	numShort := numBlocks - raw%numBlocks
	shortLen := raw / numBlocks
	div := rsDivisor(eccLen)
	blocks := make([][]byte, numBlocks)
	for i, k := 0, 0; i < numBlocks; i++ {
		l := shortLen - eccLen
		if i >= numShort {
			l++
		}
		d := data[k : k+l]
		k += l
		b := append([]byte{}, d...)
		if i < numShort {
			b = append(b, 0) // placeholder, skipped below, so every block has the same length
		}
		blocks[i] = append(b, rsRemainder(d, div)...)
	}
	out := make([]byte, 0, raw)
	for i := 0; i < len(blocks[0]); i++ {
		for j, b := range blocks {
			if i != shortLen-eccLen || j >= numShort {
				out = append(out, b[i])
			}
		}
	}
	return out
}

func gfMul(x, y byte) byte { // in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1
	z := 0
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x11D
		z ^= int(y>>i&1) * int(x)
	}
	return byte(z)
}

func rsDivisor(degree int) []byte {
	res := make([]byte, degree)
	res[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := range res {
			res[j] = gfMul(res[j], root)
			if j+1 < len(res) {
				res[j] ^= res[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return res
}

func rsRemainder(data, div []byte) []byte {
	res := make([]byte, len(div))
	for _, b := range data {
		f := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i := range res {
			res[i] ^= gfMul(div[i], f)
		}
	}
	return res
}

// drawCodewords lays the bits in the zigzag from the bottom right, skipping function modules.
func (q *qrCode) drawCodewords(data []byte) {
	n, i := q.size, 0
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < n; vert++ {
			for j := 0; j < 2; j++ {
				x, y := right-j, vert
				if (right+1)&2 == 0 {
					y = n - 1 - vert
				}
				if !q.fixed[y][x] && i < len(data)*8 {
					q.dark[y][x] = data[i>>3]>>(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func (q *qrCode) mask(m int) {
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if q.fixed[y][x] {
				continue
			}
			var inv bool
			switch m {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			q.dark[y][x] = q.dark[y][x] != inv
		}
	}
}

// penalty scores a masked code the way the standard does: long runs, 2×2 blocks, finder look-alikes,
// and an uneven share of dark modules. Lower is easier to scan.
func (q *qrCode) penalty() int {
	n, score, darkCount := q.size, 0, 0
	at := func(a, b int, rows bool) bool {
		if rows {
			return q.dark[a][b]
		}
		return q.dark[b][a]
	}
	finder := [...]bool{true, false, true, true, true, false, true}
	for _, rows := range []bool{true, false} {
		for a := 0; a < n; a++ {
			run := 1
			for b := 1; b <= n; b++ {
				if b < n && at(a, b, rows) == at(a, b-1, rows) {
					run++
					continue
				}
				if run >= 5 {
					score += run - 2
				}
				run = 1
			}
			for b := 0; b+7 <= n; b++ { // 1011101 with four light modules (or the edge) on one side
				match := true
				for k := 0; k < 7 && match; k++ {
					match = at(a, b+k, rows) == finder[k]
				}
				if !match {
					continue
				}
				light := func(from, to int) bool {
					for k := from; k < to; k++ {
						if k >= 0 && k < n && at(a, k, rows) {
							return false
						}
					}
					return true
				}
				if light(b-4, b) || light(b+7, b+11) {
					score += 40
				}
			}
		}
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if q.dark[y][x] {
				darkCount++
			}
			if x+1 < n && y+1 < n && q.dark[y][x] == q.dark[y][x+1] && q.dark[y][x] == q.dark[y+1][x] && q.dark[y][x] == q.dark[y+1][x+1] {
				score += 3
			}
		}
	}
	return score + abs(darkCount*20-n*n*10)/(n*n)*10
}

// printQR draws text as a QR code with half-block characters, black on white whatever the terminal's
// colours are, with the quiet zone the standard asks for.
func printQR(w io.Writer, text, indent string) error {
	m, err := qrEncode(text)
	if err != nil {
		return err
	}
	const quiet = 4
	n := len(m)
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < n && y < n && m[y][x]
	}
	var sb strings.Builder
	for y := 0; y < n+2*quiet; y += 2 {
		sb.WriteString(indent + "\x1b[30;107m")
		for x := 0; x < n+2*quiet; x++ {
			switch top, bottom := dark(x, y), dark(x, y+1); {
			case top && bottom:
				sb.WriteString("█")
			case top:
				sb.WriteString("▀")
			case bottom:
				sb.WriteString("▄")
			default:
				sb.WriteString(" ")
			}
		}
		sb.WriteString("\x1b[0m\n")
	}
	_, err = io.WriteString(w, sb.String())
	return err
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// runQR is `age-plugin-yubikey-phone qr TEXT`: the code alone, for scripts that show a pairing link themselves.
func runQR(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: qr TEXT")
	}
	return printQR(os.Stdout, args[0], "")
}
