# A Vault API compatible proxy for Credhub
This project is an attempt to implement the basic CRUD operations of the [Key Value API of Vault](https://www.vaultproject.io/api/index.html).

## Staring proxy

```
export CREDHUB_SERVER=...
export CREDHUB_CA_CERT=path_to_ca.pem
go run main.go
```

## Use with safe
Make sure to [install the safe cli](https://github.com/starkandwayne/safe)

```
safe target http://127.0.0.1:8200 dev
echo "${CREDHUB_CLIENT}:${CREDHUB_SECRET}" | safe auth token
safe tree /
```

By default `safe tree` will look up `/secret` tree, which is a common Vault root tree. Explicitly using `safe tree /` will look up the entire directory within Credhub. For example:

```
$ safe tree /
.
└──
    ├── /concourse/main/bucc_version
    ├── /concourse/main/concourse_worker_key
    ├── /concourse/main/concourse_tsa_host_key
    ├── /concourse/main/concourse_tsa_host
    ├── /concourse/main/concourse_ca_cert
    ├── /concourse/main/concourse_password
    ├── /concourse/main/concourse_username
    ├── /concourse/main/concourse_url
    ├── /concourse/main/credhub_ca_cert
    ├── /concourse/main/credhub_password
    ├── /concourse/main/credhub_username
    ├── /concourse/main/credhub_url
    ├── /concourse/main/bosh_stemcell
    ├── /concourse/main/bosh_cpi
    ├── /concourse/main/bosh_ssh_username
    ├── /concourse/main/bosh_ssh_private_key
    ├── /concourse/main/bosh_client
    ├── /concourse/main/bosh_client_secret
    ├── /concourse/main/bosh_ca_cert
    ├── /concourse/main/bosh_environment
    └── /concourse/main/bosh_name
```
