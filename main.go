package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"time"
)

const (
	t0 = 0
)

func main() {
	args := os.Args
	if len(args) != 2 {
		panic("set optauth")
	}

	optAuth, err := ParseOptAuthURL(args[1])
	if err != nil {
		panic(err)
	}
	totp, err := TOTP(optAuth.Secret, t0, optAuth.Period, optAuth.Digits)
	if err != nil {
		panic(err)
	}
	fmt.Println(totp)
}

func TOTP(key []byte, t, interval int64, digit int) (uint64, error) {
	counter := int((time.Now().UTC().Unix() - t) / interval)
	hash, err := hmacSha1(key, counter)
	if err != nil {
		return 0, err
	}

	sNum, err := truncate(hash)
	if err != nil {
		return 0, err
	}

	hotp := sNum % uint64(math.Pow10(digit))
	return hotp, nil
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
