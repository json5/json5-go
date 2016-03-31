package json5

func Unmarshal(data []byte, v interface{}) error {
	return nil
}

type Unmarshaler interface {
	UnmarshalJSON5([]byte) error
}
