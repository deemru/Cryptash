# Cryptash

[![packagist](https://img.shields.io/packagist/v/deemru/cryptash.svg)](https://packagist.org/packages/deemru/cryptash) [![php-v](https://img.shields.io/packagist/php-v/deemru/cryptash.svg)](https://packagist.org/packages/deemru/cryptash) [![GitHub](https://img.shields.io/github/actions/workflow/status/deemru/Cryptash/php.yml?label=github%20actions)](https://github.com/deemru/Cryptash/actions/workflows/php.yml) [![codacy](https://img.shields.io/codacy/grade/e96997be454146f9acf72aae01c604ca.svg?label=codacy)](https://app.codacy.com/gh/deemru/Cryptash/files) [![license](https://img.shields.io/packagist/l/deemru/cryptash.svg)](https://packagist.org/packages/deemru/cryptash)

[Cryptash](https://github.com/deemru/Cryptash) implements hash based encryption with user-defined size of [IV](https://en.wikipedia.org/wiki/Initialization_vector) and [MAC](https://en.wikipedia.org/wiki/Message_authentication_code).

It is a pretty simple way to protect and verify your data transfers which goes outside.

## Usage

```php
$cryptash = new Cryptash( 'Password' );
$msg = 'Hello, world!';

$encrypted = $cryptash->encryptash( $msg );
$decrypted = $cryptash->decryptash( $encrypted );

if( $decrypted !== $msg )
    exit( 1 );
```

## Requirements

- [PHP](http://php.net) >=5.4

## Installation

Require through Composer:

```json
{
    "require": {
        "deemru/cryptash": "1.0.*"
    }
}
```
