What the hosted service actually does

The Identity Service issues and validates signed agent credentials. Each credential is a JWT-SVID signed with an RSA keypair we manage per customer. TTLs are short (configurable, minimum 5 minutes, maximum 24 hours). We handle key rotation automatically — developers never think about it. Downstream services verify tokens offline against the public JWKS endpoint, with no shared secret.
