package json5

import (
	"fmt"
	"io"
	"math"
)

type parser struct {
	lexer     *lexer
	state     int
	root      interface{}
	container interface{}
	stack     []interface{}
	parsed    bool
}

func newParser(rd io.Reader) *parser {
	return &parser{lexer: newLexer(rd)}
}

func (p *parser) parse() (v interface{}, err error) {
	p.state = stateValue
	var key string

start:
	t, err := p.lexer.lex()

state:
	switch p.state {
	case stateValue:
		switch t.tokenType {
		case typeString:
			p.add(t.string(), key)
			goto start

		case typeNumber:
			p.add(t.number(), key)
			goto start

		case typePunctuator:
			switch t.rune() {
			case '[':
				p.add(make([]interface{}, 0), key)
				goto start

			case '{':
				p.add(make(map[string]interface{}), key)
				goto start
			}

			err = invalidToken(t)
			return

		case typeIdentifier:
			switch t.input {
			case "true":
				p.add(true, key)
				goto start

			case "false":
				p.add(false, key)
				goto start

			case "null":
				p.add(nil, key)
				goto start

			case "Infinity":
				p.add(math.Inf(1), key)
				goto start

			case "NaN":
				p.add(math.NaN(), key)
				goto start
			}
		}

	case stateBeforeArrayElement:
		if t.tokenType == typePunctuator && t.rune() == ']' {
			p.pop()
			goto start
		}

		p.state = stateValue
		goto state

	case stateAfterArrayElement:
		if t.tokenType == typePunctuator {
			switch t.rune() {
			case ',':
				p.state = stateBeforeArrayElement
				goto start

			case ']':
				p.pop()
				goto start
			}
		}

	case stateBeforeObjectKey:
		switch t.tokenType {
		case typePunctuator:
			if t.rune() == '}' {
				p.pop()
				goto start
			}

			break

		case typeIdentifier, typeString, typeNumber:
			key = t.string()
			p.state = stateAfterObjectKey
			goto start
		}

	case stateAfterObjectKey:
		if t.tokenType != typePunctuator || t.rune() != ':' {
			break
		}

		p.state = stateValue
		goto start

	case stateAfterObjectValue:
		if t.tokenType == typePunctuator {
			switch t.rune() {
			case ',':
				p.state = stateBeforeObjectKey
				goto start

			case '}':
				p.pop()
				goto start
			}
		}

	case stateEnd:
		if err == io.EOF {
			v, err = p.root, nil
			return
		}
	}

	if err == io.EOF {
		err = p.lexer.invalidEOF()
		return
	}

	err = invalidToken(t)
	return
}

func (p *parser) add(v interface{}, key string) {
	if p.root == nil {
		p.root = v
	}

	switch c := p.container.(type) {
	case []interface{}:
		c = append(c, v)
	case map[string]interface{}:
		c[key] = v
	}

	switch v.(type) {
	case []interface{}, map[string]interface{}:
		p.push(v)
	default:
		p.resetState()
	}
}

func (p *parser) push(v interface{}) {
	p.stack = append(p.stack, v)
	p.container = v

	switch v.(type) {
	case []interface{}:
		p.state = stateBeforeArrayElement
	case map[string]interface{}:
		p.state = stateBeforeObjectKey
	}
}

func (p *parser) pop() {
	p.stack = p.stack[:len(p.stack)-1]
	p.container = p.stack[len(p.stack)-1]
	p.resetState()
}

func (p *parser) resetState() {
	switch p.container.(type) {
	case nil:
		p.state = stateEnd
	case []interface{}:
		p.state = stateAfterArrayElement
	case map[string]interface{}:
		p.state = stateAfterObjectValue
	}
}

func invalidToken(t token) error {
	return &SyntaxError{fmt.Sprintf("json5: invalid input '%v'", t.input), t.line, t.column}
}

const (
	stateBeforeArrayElement = iota
	stateAfterArrayElement
	stateBeforeObjectKey
	stateAfterObjectKey
	stateAfterObjectValue
	stateValue
	stateEnd
)
