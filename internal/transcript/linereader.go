package transcript

import (
	"bufio"
	"bytes"
	"io"
)

// LineReader streams newline-terminated JSONL lines with a length cap and
// counts the bytes it has consumed, so a caller can resume a growing file at
// the position after the last complete line. Load uses it, and so does the
// session index.
type LineReader struct {
	r       *bufio.Reader
	maxLine int
	buf     []byte
	// Consumed is the number of bytes read through the end of the last line
	// that ended in "\n", including lines drained as too long. A final line
	// without a newline (a write in progress) is not counted, so Consumed is
	// always a safe resume offset.
	Consumed int64
}

// NewLineReader wraps r. maxLine <= 0 means DefaultMaxLine.
func NewLineReader(r io.Reader, maxLine int) *LineReader {
	if maxLine <= 0 {
		maxLine = DefaultMaxLine
	}
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, readerBuf)
	}
	return &LineReader{r: br, maxLine: maxLine}
}

// Next returns the next line without its newline (and without a trailing
// "\r"). tooLong marks a line over the cap that was drained through its
// newline; partial marks a final line without a newline; ok is false at a
// clean EOF. The returned slice is valid until the next call.
func (lr *LineReader) Next() (line []byte, tooLong, partial, ok bool) {
	lr.buf = lr.buf[:0]
	var n int64
	for {
		chunk, err := lr.r.ReadSlice('\n')
		n += int64(len(chunk))
		switch err {
		case nil:
			lr.Consumed += n
			if tooLong {
				return nil, true, false, true
			}
			if len(lr.buf) == 0 {
				line = chunk[:len(chunk)-1]
			} else {
				lr.buf = append(lr.buf, chunk[:len(chunk)-1]...)
				line = lr.buf
			}
			if len(line) > lr.maxLine {
				return nil, true, false, true
			}
			return bytes.TrimSuffix(line, []byte{'\r'}), false, false, true
		case bufio.ErrBufferFull:
			if !tooLong {
				lr.buf = append(lr.buf, chunk...)
				if len(lr.buf) > lr.maxLine {
					tooLong = true
					lr.buf = lr.buf[:0]
				}
			}
		default: // io.EOF or a read error: no newline terminates what is left
			if len(chunk) > 0 || len(lr.buf) > 0 || tooLong || n > 0 {
				return nil, tooLong, true, true
			}
			return nil, false, false, false
		}
	}
}
