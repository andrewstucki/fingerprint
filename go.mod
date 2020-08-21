module github.com/andrewstucki/fingerprint

go 1.14

require (
	github.com/go-errors/errors v1.0.2
	github.com/h2non/filetype v1.0.12
	github.com/knightsc/gapstone v4.0.1+incompatible
	github.com/minio/sha256-simd v0.1.1
	github.com/stretchr/testify v1.5.1
)

replace github.com/h2non/filetype => ../filetype
