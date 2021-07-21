module github.com/nats-io/jwt/v2

replace github.com/nats-io/nkeys v0.3.0 => github.com/zenovich/nkeys v0.3.1-0.20210720235559-43e243885d59

require (
	github.com/nats-io/jwt v1.2.2
	github.com/nats-io/nkeys v0.3.0
)

replace github.com/nats-io/jwt v1.2.2 => ../

go 1.14
