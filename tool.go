package main

import (
	"fmt"
	"io"
)

func readN(r io.Reader, n byte) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid read length: %d", n)
	}

	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
