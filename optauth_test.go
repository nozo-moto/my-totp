package main

import (
	"encoding/base32"
	"reflect"
	"testing"
)

func TestParseOptAuthURL(t *testing.T) {
	secretKey := []byte("twitter")
	secret := make([]byte, base32.StdEncoding.EncodedLen(len(secretKey)))
	base32.StdEncoding.Encode(secret, secretKey)

	tests := []struct {
		name    string
		optUrl  string
		want    *OptAuth
		wantErr bool
	}{
		{
			name:   "success",
			optUrl: "otpauth://totp/Twitter?algorithm=SHA1&digits=6&period=30&secret=OR3WS5DUMVZA====",
			want: &OptAuth{
				Service:   "Twitter",
				Algorithm: "SHA1",
				Digits:    6,
				Period:    30,
				Secret:    secret,
			},
			wantErr: false,
		},
		{
			name:    "fail digits",
			optUrl:  "otpauth://totp/Twitter?algorithm=SHA1&digits=six&period=30&secret=OR3WS5DUMVZA",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "fail period",
			optUrl:  "otpauth://totp/Twitter?algorithm=SHA1&digits=6&period=thirty&secret=OR3WS5DUMVZA",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseOptAuthURL(tt.optUrl)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOptAuthURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseOptAuthURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
