# go-ecodec

[![Tag](https://img.shields.io/github/tag/wealdtech/go-ecodec.svg)](https://github.com/wealdtech/go-ecodec/releases/)
[![License](https://img.shields.io/github/license/wealdtech/go-ecodec.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/wealdtech/go-ecodec?status.svg)](https://godoc.org/github.com/wealdtech/go-ecodec)
[![Travis CI](https://img.shields.io/travis/wealdtech/go-ecodec.svg)](https://travis-ci.org/wealdtech/go-ecodec)
[![codecov.io](https://img.shields.io/codecov/c/github/wealdtech/go-ecodec.svg)](https://codecov.io/github/wealdtech/go-ecodec)
[![Go Report Card](https://goreportcard.com/badge/github.com/wealdtech/go-ecodec)](https://goreportcard.com/report/github.com/wealdtech/go-ecodec)

Go module providing encryption and decryption of byte-level data.


## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

`go-ecodec` is a standard Go module which can be installed with:

```sh
go get github.com/wealdtech/go-ecodec
```

## Usage

### Example

```go
package main

import (
    "fmt"

    ecodec "github.com/wealdtech/go-ecodec"
)

func main() {
    data := []byte("The data to be encrypted")
    key := []byte("my secret passphrase")

    encryptedData, err := ecodec.Encrypt(data, key)
    if err != nil {
        panic(err)
    }

    decryptedData, err := ecodec.Decrypt(encryptedData, key)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Decrypted data is %q\n", string(decryptedData))
}
```
## Maintainers

Jim McDonald: [@mcdee](https://github.com/mcdee).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/wealdtech/go-ecodec/issues).

## License

[Apache-2.0](LICENSE) © 2019 Weald Technology Trading Ltd
