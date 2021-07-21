module github.com/nats-io/nats.go

go 1.16

replace github.com/nats-io/nkeys v0.3.0 => github.com/zenovich/nkeys v0.3.1-0.20210720235559-43e243885d59

replace github.com/nats-io/nats-server/v2 v2.3.2 => github.com/zenovich/nats-server/v2 v2.3.3-0.20210721122126-5081f3431950

replace github.com/nats-io/jwt/v2 v2.0.2 => github.com/zenovich/jwt/v2 v2.0.3-0.20210721015402-a4143f233842

require (
	github.com/golang/protobuf v1.4.3
	github.com/nats-io/nats-server/v2 v2.3.2
	github.com/nats-io/nkeys v0.3.0
	github.com/nats-io/nuid v1.0.1
	google.golang.org/protobuf v1.23.0
)
