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
$ my-totp 1Z2X3C4V
> 123456
```

