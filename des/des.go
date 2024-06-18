package des

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
)

// PKCS5Padding 按照 pkcs5 的方式进行填充
func PKCS5Padding(text []byte, blockSize int) []byte {
	// 1.(len(ciphertext) % blockSize) 是看最后一个块有多少字节。
	// 2.blockSize - (len(ciphertext) % blockSize) 是看最后一个块需要填充多少字节。
	paddingLength := blockSize - (len(text) % blockSize)
	padding := make([]byte, paddingLength)
	// 让填充的每一个字节都等于填充的字节数
	for index := 0; index < paddingLength; index++ {
		padding[index] = byte(paddingLength)
	}
	cipherTextAfterPadding := append(text, padding...)
	return cipherTextAfterPadding
}

// PKCS5Unpadding 按照 pkcs5 将填充的部分取消
func PKCS5Unpadding(text []byte) []byte {
	length := len(text)
	paddingLength := int(text[length-1])
	return text[:(length - paddingLength)]
}

// EncriptCBCMode 利用 DES 在 CBC 模式下进行加密
func EncriptCBCMode(plaintext []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)

	if len(key) != 8 {
		return nil, errors.New("密钥一定要是8字节的")
	}

	if err != nil {
		return nil, errors.New("创建 block 失败")
	}
	// block 的 size 和 key 的 size 一致
	afterPaddingPlainText := PKCS5Padding(plaintext, block.BlockSize())
	// 参数iv, iv 的长度必须等于 block 长度
	IV := []byte("AAAAAAAA")
	// 创建 cbc 模式加密器
	cbcModeCipher := cipher.NewCBCEncrypter(block, IV)
	// 创建存放密文的slice
	cipherText := make([]byte, len(afterPaddingPlainText))
	cbcModeCipher.CryptBlocks(cipherText, afterPaddingPlainText)
	return cipherText, nil
}

// DecriptCBCMode 利用 DES 在 CBC 模式下进行解密
func DecriptCBCMode(cipherText []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, errors.New("创建 block 失败")
	}
	// 参数 iv, iv 的长度必须等于 block 长度
	IV := []byte("AAAAAAAA")
	// 创建 cbc 模式解密器
	cbcModeDecriptor := cipher.NewCBCDecrypter(block, IV)
	// 创建存放明文的slice
	plainText := make([]byte, len(cipherText))
	cbcModeDecriptor.CryptBlocks(plainText, cipherText)
	// 将多余的数据去掉
	unpaddingPlainText := PKCS5Unpadding(plainText)
	return unpaddingPlainText, nil
}
