package json5

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode"
)

type lexer struct {
	reader *reader
}

func newLexer(rd io.Reader) *lexer {
	return &lexer{newReader(rd)}
}

func (l *lexer) lex() (t token, err error) {
	state := stateDefault
	sign := 1
	var (
		inputBuf, valueBuf string
		doubleQuote        bool
		line, column       int
	)

start:
	r, _, err := l.reader.ReadRune()
	if err != nil && err != io.EOF {
		return
	}

	switch state {
	case stateDefault:
		if err == io.EOF {
			return
		}

		switch r {
		case '\t', '\v', '\f', 0x00A0, 0xFEFF, '\n', '\r', 0x2028, 0x2029:
			// Skip whitespace. More whitespace is checked for after this switch.
			goto start

		case '/':
			state = stateComment
			goto start

		case '$', '_':
			// $ and _ are valid identifiers. More identifiers are checked for after
			// this switch.
			state = stateIdentifier
			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case '\\':
			state = stateIdentifierStartEscapeSlash
			inputBuf = string(r)
			goto start

		case '{', '}', '[', ']', ',', ':':
			t = l.newToken(typePunctuator, string(r))
			return

		case '+', '-':
			state = stateSign
			if r == '-' {
				sign = -1
			}

			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case '0':
			state = stateZero
			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case '1', '2', '3', '4', '5', '6', '7', '8', '9':
			state = stateDecimalInteger
			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case '.':
			state = stateDecimalPointLeading
			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case '"', '\'':
			state = stateString
			doubleQuote = r == '"'
			inputBuf += string(r)
			line, column = l.reader.line, l.reader.column
			goto start
		}

		if unicode.Is(unicode.Zs, r) {
			// Skip witespace.
			goto start
		}

		if unicode.In(r, unicode.L, unicode.Nl) {
			state = stateIdentifier
			inputBuf += string(r)
			valueBuf += string(r)
			goto start
		}

		err = l.invalidChar(r)
		return

	case stateComment:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		switch r {
		case '*':
			state = stateMultiLineComment
			goto start

		case '/':
			state = stateSingleLineComment
			goto start
		}

		err = l.invalidChar(r)
		return

	case stateMultiLineComment:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		if r == '*' {
			state = stateMultiLineCommentAsterisk
		}

		goto start

	case stateMultiLineCommentAsterisk:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		if r == '/' {
			state = stateDefault
		} else {
			state = stateMultiLineComment
		}

		goto start

	case stateSingleLineComment:
		if err == io.EOF {
			return
		}

		switch r {
		case '\n', '\r', '\u2028', '\u2029':
			state = stateDefault
		}

		goto start

	case stateIdentifier:
		if err != io.EOF {
			switch r {
			case '$', '_':
				inputBuf += string(r)
				valueBuf += string(r)
				goto start

			case '\\':
				state = stateIdentifierEscapeSlash
				inputBuf += string(r)
				goto start
			}

			if isUnicodeIDRune(r) {
				inputBuf += string(r)
				valueBuf += string(r)
				goto start
			}
		}

		t, err = l.newToken(typeIdentifier, inputBuf), nil
		return

	case stateIdentifierStartEscapeSlash, stateIdentifierEscapeSlash:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		if r != 'u' {
			err = l.invalidChar(r)
			return
		}

		inputBuf += string(r)
		var hexBuf string
		for i := 0; i < 4; i++ {
			r, _, err = l.reader.ReadRune()
			if err != nil {
				if err == io.EOF {
					err = l.invalidEOF()
				}

				return
			}

			if !isHexDigit(r) {
				err = l.invalidChar(r)
				return
			}

			inputBuf += string(r)
			hexBuf += string(r)
		}

		// f will test if the escaped rune is an IdentifierStart or IdentifierPart
		// depending on the state.
		var f func(rune) bool
		if state == stateIdentifierStartEscapeSlash {
			f = isUnicodeIDStartRune
		} else {
			f = isUnicodeIDRune
		}

		n, _ := strconv.ParseUint(hexBuf, 16, 16)
		u := rune(n)
		if u == '$' || u == '_' || f(u) {
			state = stateIdentifier
			valueBuf += string(u)
			goto start
		}

		err = l.invalidEscape(u)
		return

	case stateSign:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		switch r {
		case '0':
			state = stateZero
			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case '1', '2', '3', '4', '5', '6', '7', '8', '9':
			state = stateDecimalInteger
			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case '.':
			state = stateDecimalPointLeading
			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case 'I':
			inputBuf += string(r)
			valueBuf += string(r)

			for _, i := range "nfinity" {
				r, _, err = l.reader.ReadRune()
				if err != nil {
					if err == io.EOF {
						err = l.invalidEOF()
					}

					return
				}

				if r != i {
					err = l.invalidChar(r)
					return
				}

				inputBuf += string(r)
				valueBuf += string(r)
			}

			l.newTokenV(typeNumber, inputBuf, math.Inf(sign))
			return

		case 'N':
			inputBuf += string(r)
			valueBuf += string(r)

			for _, i := range "aN" {
				r, _, err = l.reader.ReadRune()
				if err != nil {
					if err == io.EOF {
						err = l.invalidEOF()
					}

					return
				}

				if r != i {
					err = l.invalidChar(r)
					return
				}

				inputBuf += string(r)
				valueBuf += string(r)
			}

			l.newTokenV(typeNumber, inputBuf, math.NaN())
			return
		}

		err = l.invalidChar(r)
		return

	case stateZero:
		if err != io.EOF {
			switch r {
			case '.':
				state = stateDecimalPoint
				inputBuf += string(r)
				valueBuf += string(r)
				goto start

			case 'e', 'E':
				state = stateDecimalExponent
				inputBuf += string(r)
				valueBuf += string(r)
				goto start

			case 'x', 'X':
				state = stateHexadecimal
				inputBuf += string(r)
				valueBuf = ""
				goto start

			case '0', '1', '2', '3', '4', '5', '6', '7':
				err = l.invalidOctal()
				return

			case '8', '9':
				err = l.invalidZeroPrefix()
				return
			}
		}

		t, err = l.newTokenV(typeNumber, inputBuf, 0.0), nil
		return

	case stateDecimalInteger:
		if err != io.EOF {
			switch r {
			case '.':
				state = stateDecimalPoint
				inputBuf += string(r)
				valueBuf += string(r)
				goto start

			case 'e', 'E':
				state = stateDecimalExponent
				inputBuf += string(r)
				valueBuf += string(r)
				goto start
			}

			if isDigit(r) {
				inputBuf += string(r)
				valueBuf += string(r)
				goto start
			}
		}

		n, _ := strconv.ParseFloat(valueBuf, 64)
		t, err = l.newTokenV(typeNumber, inputBuf, n), nil
		return

	case stateDecimalPointLeading:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		if isDigit(r) {
			state = stateDecimalFraction
			inputBuf += string(r)
			valueBuf += string(r)
			goto start
		}

		err = l.invalidChar(r)
		return

	case stateDecimalPoint:
		if err != io.EOF {
			switch r {
			case 'e', 'E':
				state = stateDecimalExponent
				inputBuf += string(r)
				valueBuf += string(r)
				goto start
			}

			if isDigit(r) {
				state = stateDecimalFraction
				inputBuf += string(r)
				valueBuf += string(r)
				goto start
			}
		}

		n, _ := strconv.ParseFloat(valueBuf, 64)
		t, err = l.newTokenV(typeNumber, inputBuf, n), nil
		return

	case stateDecimalFraction:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		switch r {
		case '+', '-':
			state = stateDecimalExponentSign
			inputBuf += string(r)
			valueBuf += string(r)
			goto start
		}

		if isDigit(r) {
			state = stateDecimalExponentInteger
			inputBuf += string(r)
			valueBuf += string(r)
			goto start
		}

		err = l.invalidChar(r)
		return

	case stateDecimalExponentSign:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		if isDigit(r) {
			state = stateDecimalExponentInteger
			inputBuf += string(r)
			valueBuf += string(r)
			goto start
		}

		err = l.invalidChar(r)
		return

	case stateDecimalExponentInteger:
		if err != io.EOF && isDigit(r) {
			inputBuf += string(r)
			valueBuf += string(r)
			goto start
		}

		n, _ := strconv.ParseFloat(valueBuf, 64)
		t, err = l.newTokenV(typeNumber, inputBuf, n), nil
		return

	case stateHexadecimal:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		if isHexDigit(r) {
			state = stateHexadecimalInteger
			inputBuf += string(r)
			valueBuf += string(r)
			goto start
		}

		err = l.invalidChar(r)
		return

	case stateHexadecimalInteger:
		if err != io.EOF && isHexDigit(r) {
			state = stateHexadecimalInteger
			inputBuf += string(r)
			valueBuf += string(r)
			goto start
		}

		n, _ := strconv.ParseFloat(valueBuf, 64)
		t, err = l.newTokenV(typeNumber, inputBuf, n), nil
		return

	case stateString:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		switch r {
		case '\\':
			state = stateEscape
			inputBuf += string(r)
			goto start

		case '"', '\'':
			if doubleQuote && r == '"' {
				inputBuf += string(r)
				t = l.newTokenVPos(typeString, inputBuf, valueBuf, line, column)
				return
			}

			inputBuf += string(r)
			valueBuf += string(r)
			goto start

		case '\n', '\r':
			err = l.invalidChar(r)
			return
		}

		inputBuf += string(r)
		valueBuf += string(r)
		goto start

	case stateEscape:
		if err == io.EOF {
			err = l.invalidEOF()
			return
		}

		switch r {
		case 'b':
			state = stateString
			inputBuf += string(r)
			valueBuf += string('\b')
			goto start

		case 'f':
			state = stateString
			inputBuf += string(r)
			valueBuf += string('\f')
			goto start

		case 'n':
			state = stateString
			inputBuf += string(r)
			valueBuf += string('\n')
			goto start

		case 'r':
			state = stateString
			inputBuf += string(r)
			valueBuf += string('\r')
			goto start

		case 't':
			state = stateString
			inputBuf += string(r)
			valueBuf += string('\t')
			goto start

		case 'v':
			state = stateString
			inputBuf += string(r)
			valueBuf += string('\v')
			goto start

		case '0':
			var p rune
			p, _, err = l.reader.ReadRune()
			if err != nil {
				if err == io.EOF {
					err = l.invalidEOF()
				}

				return
			}

			if isDigit(p) {
				err = l.invalidOctal()
				return
			}

			if err = l.reader.UnreadRune(); err != nil {
				return
			}

			state = stateString
			inputBuf += string(r)
			valueBuf += string(rune(0))
			goto start

		case 'x':
			inputBuf += string(r)
			var hexBuf string
			for i := 0; i < 2; i++ {
				r, _, err = l.reader.ReadRune()
				if err != nil {
					if err == io.EOF {
						err = l.invalidEOF()
					}

					return
				}

				if !isHexDigit(r) {
					err = l.invalidChar(r)
					return
				}

				inputBuf += string(r)
				hexBuf += string(r)
			}

			n, _ := strconv.ParseUint(hexBuf, 16, 8)
			valueBuf += string(rune(n))
			state = stateString
			goto start

		case 'u':
			inputBuf += string(r)
			var hexBuf string
			for i := 0; i < 4; i++ {
				r, _, err = l.reader.ReadRune()
				if err != nil {
					if err == io.EOF {
						err = l.invalidEOF()
					}

					return
				}

				if !isHexDigit(r) {
					err = l.invalidChar(r)
					return
				}

				inputBuf += string(r)
				hexBuf += string(r)
			}

			n, _ := strconv.ParseUint(hexBuf, 16, 16)
			valueBuf += string(rune(n))
			state = stateString
			goto start

		case '\n':
		case '\r':
		case '\u2028':
		case '\u2029':
			state = stateString
			inputBuf += string(r)
			if r == '\r' {
				var p rune
				p, _, err = l.reader.ReadRune()
				if err != nil {
					if err == io.EOF {
						err = l.invalidEOF()
					}

					return
				}

				if p == '\n' {
					inputBuf += string(r)
				} else if err = l.reader.UnreadRune(); err != nil {
					return
				}
			}

			goto start
		}

		state = stateString
		inputBuf += string(r)
		valueBuf += string(r)
		goto start
	}

	err = errors.New("json5: invalid state - data changed under foot?")
	return
}

func (l *lexer) newToken(tokenType int, input string) token {
	return token{tokenType, input, input, l.reader.line, l.reader.column}
}

func (l *lexer) newTokenV(tokenType int, input string, value interface{}) token {
	return token{tokenType, input, value, l.reader.line, l.reader.column}
}

func (l *lexer) newTokenVPos(tokenType int, input string, value interface{}, line, column int) token {
	return token{tokenType, input, value, l.reader.line, l.reader.column}
}

func (l *lexer) invalidChar(r rune) *SyntaxError {
	return &SyntaxError{fmt.Sprintf("json5: invalid character '%v'", r), l.reader.line, l.reader.column}
}

func (l *lexer) invalidCharPos(r rune, line, column int) *SyntaxError {
	return &SyntaxError{fmt.Sprintf("json5: invalid character '%v'", r), line, column}
}

func (l *lexer) invalidEOF() *SyntaxError {
	return &SyntaxError{"json5: invalid end of input", l.reader.line, l.reader.column}
}

func (l *lexer) invalidEscape(r rune) *SyntaxError {
	return &SyntaxError{fmt.Sprintf("json5: invalid escape '\\u%X' in object key", r), l.reader.line, l.reader.column}
}

func (l *lexer) invalidOctal() *SyntaxError {
	return &SyntaxError{"json5: octal numbers are not supported", l.reader.line, l.reader.column}
}

func (l *lexer) invalidOctalEscape() *SyntaxError {
	return &SyntaxError{"json5: octal escapes are not supported", l.reader.line, l.reader.column}
}

func (l *lexer) invalidZeroPrefix() *SyntaxError {
	return &SyntaxError{"json5: non-zero numbers must not start with zero", l.reader.line, l.reader.column}
}

func isUnicodeIDStartRune(r rune) bool {
	return unicode.In(r, unicode.L, unicode.Nl)
}

func isUnicodeIDRune(r rune) bool {
	return unicode.In(r,
		unicode.L,
		unicode.Nl,
		unicode.Mn,
		unicode.Mc,
		unicode.Nd,
		unicode.Pc)
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func isHexDigit(r rune) bool {
	return r >= '0' && r <= '9' ||
		r >= 'A' && r <= 'Z' ||
		r >= 'a' && r <= 'z'
}

type reader struct {
	rd                       *bufio.Reader
	last                     rune
	line, column, lastColumn int
}

func newReader(rd io.Reader) *reader {
	return &reader{rd: bufio.NewReader(rd), line: 1, column: 1}
}

func (b *reader) ReadRune() (r rune, size int, err error) {
	r, size, err = b.rd.ReadRune()
	if err != nil {
		return
	}

	if r == '\n' {
		b.line++
		b.lastColumn = b.column
		b.column = 1
	} else {
		b.column++
	}

	b.last = r
	return
}

func (b *reader) UnreadRune() error {
	err := b.rd.UnreadRune()
	if err != nil {
		return err
	}

	if b.last == '\n' {
		b.line--
		b.column = b.lastColumn
	} else {
		b.column--
	}

	return nil
}

type token struct {
	tokenType    int
	input        string
	value        interface{}
	line, column int
}

func (t *token) rune() rune {
	return t.value.(rune)
}

func (t *token) number() float64 {
	return t.value.(float64)
}

func (t *token) string() string {
	return t.value.(string)
}

const (
	typeNone = iota
	typeIdentifier
	typeNumber
	typePunctuator
	typeString
)

const (
	stateDefault = iota
	stateComment
	stateMultiLineComment
	stateMultiLineCommentAsterisk
	stateSingleLineComment
	stateIdentifier
	stateIdentifierStartEscapeSlash
	stateIdentifierEscapeSlash
	stateSign
	stateZero
	stateDecimalInteger
	stateDecimalPointLeading
	stateDecimalPoint
	stateDecimalFraction
	stateDecimalExponent
	stateDecimalExponentSign
	stateDecimalExponentInteger
	stateHexadecimal
	stateHexadecimalInteger
	stateString
	stateEscape
)

type SyntaxError struct {
	msg          string
	Line, Column int
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf(e.msg+" at line %v, column %v", e.Line, e.Column)
}
