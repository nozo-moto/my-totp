package main

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
)

func Test_truncate(t *testing.T) {
	tests := []struct {
		name    string
		hash    []byte
		want    uint64
		wantErr bool
	}{
		{
			name: "success",
			hash: []byte{
				0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a,
			},
			want:    uint64(1357872921),
			wantErr: false,
		},
		{
			name: "invalid bytes array length 21",
			hash: []byte{
				0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a, 0x11,
			},
			want:    uint64(0),
			wantErr: true,
		},
		{
			name: "invalid bytes array length 19",
			hash: []byte{
				0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55,
			},
			want:    uint64(0),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := truncate(tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("truncate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("truncate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hmacSha1(t *testing.T) {
	key := []byte("12345678901234567890")
	n1 := new(big.Int)
	n1, _ = n1.SetString("cc93cf18508d94934c64b65d8ba7667fb7cde4b0", 16)
	n2 := new(big.Int)
	n2, _ = n2.SetString("75a48a19d4cbe100644e8ac1397eea747a2d33ab", 16)
	n3 := new(big.Int)
	n3, _ = n3.SetString("0bacb7fa082fef30782211938bc1c5e70416ff44", 16)

	type args struct {
		key     []byte
		counter int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				key:     key,
				counter: 0,
			},
			want:    n1.Bytes(),
			wantErr: false,
		},
		{
			name: "success",
			args: args{
				key:     key,
				counter: 1,
			},
			want:    n2.Bytes(),
			wantErr: false,
		},
		{
			name: "success",
			args: args{
				key:     key,
				counter: 2,
			},
			want:    n3.Bytes(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hmacSha1(tt.args.key, tt.args.counter)
			if (err != nil) != tt.wantErr {
				t.Errorf("hmacSha1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Logf("got: %v, want: %v", hex.EncodeToString(got), hex.EncodeToString(tt.want))
				t.Errorf("hmacSha1() = %v, want %v", got, tt.want)
			}
		})
	}
}
