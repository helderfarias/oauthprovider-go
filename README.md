# oauthprovider-go
The OAuth 2.0 Authorization Framework

## Certs
```bash
openssl ecparam -genkey -name secp521r1 -noout -out private.pem 
openssl ec -in private.pem -pubout -out public.pem
```