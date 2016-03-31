package json5

func Marshal(v interface{}) ([]byte, error) {
	return nil, nil
}

type Marshaler interface {
	MarshalJSON5([]byte, error)
}
