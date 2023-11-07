# JWT

`jwt` is a command line utility to create and verify JSON Web Tokens.

## Install

Either download a [pre-built binary](https://github.com/jamescun/jwt/releases), or install from source (requires Go 1.21+):

```sh
go install github.com/jamescun/jwt@latest
```

Alternatively on macOS, you can install jwt using the Homebrew package manager:

```sh
brew install jamescun/formulas/jwt
```

## Usage

If you don't already have a private key to sign your JSON Web Tokens with, one can be generated with:

```sh
jwt key --ed25519
```

Which will write an Ed25519 private key to a file called `key.pem`.

To generate a JSON Web Token using this private key:

```sh
jwt sign --aud alice --sub bob
```

Which will generate a signed JSON Web Token with an audience of `alice`, for the subject `bob` that expires in 24 hours.

```
eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJhbGljZSIsImV4cCI6MTY5OTQ1Njc3OCwiaWF0IjoxNjk5MzcwMzc4LCJpc3MiOiJnaXRodWIuY29tL2phbWVzY3VuL2p3dCIsIm5iZiI6MTY5OTM3MDM3OCwic3ViIjoiYm9iIn0.EvBPiqBbMH6DdUo-wmHKl4Pgu0-UzbEreE8eQI7dC6DR07F0IinX-dRlWpI5rOK00fMwbjUTKVAyhL7JMfiOCw
```

To control the expiry, use the `--exp` command line flag, which accepts s(econds), m(inutes) or h(ours).

Custom claims can also be added with the `--claim key='"value"'` command line flag. The value must be valid JSON, i.e.:

```sh
jwt sign --claim 'human="true"' --claim 'scopes=["foo","bar"]'
```
