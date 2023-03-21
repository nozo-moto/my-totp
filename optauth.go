package main

import (
	"encoding/base32"
	"net/url"
	"strconv"
)

type OptAuth struct {
	Service   string
	Algorithm string
	Digits    int
	Period    int64
	Secret    []byte
}

func ParseOptAuthURL(optUrl string) (*OptAuth, error) {
	u, err := url.Parse(optUrl)
	if err != nil {
		return nil, err
	}

	o := &OptAuth{
		Service: u.Path[1:len(u.Path)],
	}

	for k, vs := range u.Query() {
		for _, v := range vs {
			switch k {
			case "digits":
				digits, err := strconv.Atoi(v)
				if err != nil {
					return nil, err
				}
				o.Digits = digits
			case "period":
				period, err := strconv.Atoi(v)
				if err != nil {
					return nil, err
				}
				o.Period = int64(period)
			case "algorithm":
				o.Algorithm = v
			case "secret":
				secret := []byte(v)
				key := make([]byte, base32.StdEncoding.DecodedLen(len(secret)))
				_, err := base32.StdEncoding.Decode(key, []byte(secret))
				if err != nil {
					return nil, err
				}
				o.Secret = key
			}
		}
	}

	return o, nil
}
