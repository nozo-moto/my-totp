package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	digit = 6
)

func main() {
	key := []byte("12345678901234567890")
	totp := TOTP(key, time.Now().Add(time.Second*-10000).Unix(), 30)
	fmt.Println(totp)
}

func TOTP(key []byte, t int64, interval int) uint64 {
	counter := int((time.Now().Unix() - t) / int64(interval))
	hash, err := hmacSha1(key, counter)
	if err != nil {
		panic(err)
	}

	sNum, err := truncate(hash)
	if err != nil {
		panic(err)
	}

	hotp := sNum % uint64(math.Pow10(digit))
	return hotp
}

func hmacSha1(key []byte, counter int) ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(counter))
	hmacSha1Hash := hmac.New(sha1.New, key)
	_, err := hmacSha1Hash.Write(b)
	if err != nil {
		return nil, err
	}

	hashValue := hmacSha1Hash.Sum(nil)
	if len(hashValue) != 20 {
		return nil, fmt.Errorf("failed to generate hmac sha1 hash")
	}

	return hashValue, nil
}

func truncate(hash []byte) (uint64, error) {
	if len(hash) != 20 {
		return 0, fmt.Errorf("invalid hash")
	}
	offset := hash[19] & 0xf
	p := binary.BigEndian.Uint64(append([]byte{0, 0, 0, 0}, hash[offset:offset+4]...))
	return p & 0x7FFFFFFF, nil
}
