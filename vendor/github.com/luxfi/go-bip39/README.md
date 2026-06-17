# GO-BIP39
This repository contains a local copy of the original ``github.com/tyler-smith/go-bip39`` library.

# ⚠️ Important Notice
The original [go-bip39](https://github.com/tyler-smith/go-bip39) library by tyler-smith has been removed from GitHub.
To ensure continuity and compatibility for existing projects, this repository provides a preserved version of the library based on a previously cached local copy.

# Usage

There are two ways to use this fork in your project:

1. Replace the original path in ``go.mod``
```
replace github.com/tyler-smith/go-bip39 => github.com/luxfi/go-bip39 v1.1.0
```

2. Import directly via ``go get``
   You can also import this fork directly using:

```bash
go get github.com/luxfi/go-bip39
```

# Original README
The original README from the now-deleted repository is preserved in this repo as [tyler-smith.README.md](tyler-smith.README.md)
