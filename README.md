# my-totp

## How to use 


install 

```
go install github.com/nozo-moto/my-totp@latest
```

First, Get Base32 secret.
If you are using Google Authenticator, you can parse otpauth migration code.

https://github.com/dim13/otpauth


``` shell
$ my-totp "otpauth://totp/Twitter?algorithm=SHA1&digits=6&period=30&secret=OR3WS5DUMVZA====",
> 123456
```

