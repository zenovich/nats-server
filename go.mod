module github.com/nats-io/nats-server/v2

go 1.16

replace github.com/nats-io/nkeys v0.3.0 => github.com/zenovich/nkeys v0.3.1-0.20210720235559-43e243885d59

replace github.com/nats-io/jwt/v2 v2.0.2 => github.com/zenovich/jwt/v2 v2.0.3-0.20210721015402-a4143f233842

replace github.com/nats-io/nats.go v1.11.1-0.20210623165838-4b75fc59ae30 => github.com/zenovich/nats.go v1.11.1-0.20210721123537-d132d67e3dd0

require (
	github.com/klauspost/compress v1.11.12
	github.com/minio/highwayhash v1.0.1
	github.com/nats-io/jwt/v2 v2.0.2
	github.com/nats-io/nats.go v1.11.1-0.20210623165838-4b75fc59ae30
	github.com/nats-io/nkeys v0.3.0
	github.com/nats-io/nuid v1.0.1
	golang.org/dl v0.0.0-20210713194856-38ddc79c2163 // indirect
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1
	golang.org/x/time v0.0.0-20201208040808-7e3f01d25324
)
