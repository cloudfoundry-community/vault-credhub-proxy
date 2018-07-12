# A Vault API compatible proxy for Credhub
This project is an attempt to implement the basic CRUD operations of the [Key Value API of Vault](https://www.vaultproject.io/api/index.html).

# Staring proxy

```
export CREDHUB_SERVER=...
export CREDHUB_CA_CERT=path_to_ca.pem
go run main.go
```

# Use with safe
Make sure to [install the safe cli](https://github.com/starkandwayne/safe)

```
safe target http://127.0.0.1:8200 dev
echo "${CREDHUB_CLIENT}:${CREDHUB_SECRET}" | safe auth token
safe tree
```
