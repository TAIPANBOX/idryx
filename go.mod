module github.com/TAIPANBOX/idryx

go 1.26

toolchain go1.26.5

require github.com/jackc/pgx/v5 v5.9.2

require (
	github.com/TAIPANBOX/agent-stack-go v0.0.0
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace github.com/TAIPANBOX/agent-stack-go => ../agent-stack-go
