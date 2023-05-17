# ip-address-ts

IP addresses library in TypeScript. It defines an `Address` interface with `Address4` and `Address6` implementations.

Building on the `Address` types, the package also defines `Prefix` representing an IP network or an address block.

## Features

- IPv4 (`Address4`)
- IPv6 (`Address6`)
- Network Prefix (`Prefix`)
- Binary representation in bytes and 16-bit groups
- Text notations formatting and parsing
- ".arpa" representations formatting and parsing

## Install

```sh
npm install @dnspect/ip-address-ts
```

## Usage

```javascript
import { Address4, Address6, Prefix } from "ip-address-ts";

// Parses from text notation
const loopback4 = Address4.parse("127.0.0.1");
// Parses from in-addr.arpa representation
const loopback4 = Address4.fromArpa("1.0.0.127.in-addr.arpa.");

// Parses from text notation
const loopback6 = Address6.parse("::1");
// Parses from ip6.arpa representation
const loopback6 = Address6.fromArpa("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");

// Defines the documentation range of IPv6
const docRange = Prefix.parse("2001:db8::1/32");
```
