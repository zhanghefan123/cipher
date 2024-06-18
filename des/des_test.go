package des

import (
	"bytes"
	"fmt"
	"testing"
)

func TestDesEncryptAndDecript(t *testing.T) {
	plainText := []byte("zhf1231231231")
	key := []byte("zhf75081")
	cipherText, err := EncriptCBCMode(plainText, key)
	if err != nil {
		fmt.Println(err)
		panic("encrpt failed")
	}
	decrptText, err := DecriptCBCMode(cipherText, key)
	if err != nil {
		fmt.Println(err)
		panic("decrypt failed")
	}
	if !bytes.Equal(plainText, decrptText) {
		t.Errorf("not equal")
	}
}
