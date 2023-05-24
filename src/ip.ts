/**
 * An IP address that identifies a device on the Internet or a local network.
 */
export interface Address {
    /**
     * Returns true if it is IPv4 address, false otherwise.
     *
     * The IPv4-mapped IPv6 addresses, IPv4 translated IPv6 addresses, and 4in6
     * addresses also return true.
     */
    isIPv4(): boolean;

    /**
     * Returns true if it is IPv6 address, false otherwise.
     */
    isIPv6(): boolean;

    /**
     * Returns the number of bits of the address. v4 address is 32, v6 address is 128.
     */
    bits(): number;

    /**
     * Returns IPv6 scoped addressing zone, if any. It is empty for IPv4 address.
     */
    zone(): string;

    /**
     * Returns the canonical text representation format of the address.
     */
    toString(): string;

    /**
     * Returns the hexadecimal string representation of the address.
     */
    toHex(): string;

    /**
     * Returns reversed .arpa form of the address.
     */
    toArpa(): string;

    /**
     * Returns a reference to the underlying data.
     */
    bytes(): Uint8Array;

    /**
     * Returns a copy of the underlying data in bytes.
     */
    bytesCloned(): Uint8Array;

    /**
     * Converts the underlying data to a 16-bit array.
     */
    to16BitGroups(): Uint16Array;

    /**
     * Returns a zero-padded base-2 string representation of the address
     */
    toBinaryString(): string;

    /**
     * Returns true if it is an unspecified address, false otherwise.
     */
    isUnspecified(): boolean;

    /**
     * Returns true if it is a loopback address.
     */
    isLoopback(): boolean;

    /**
     * Returns true if it is a private address, according to RFC 1918 (IPv4 addresses)
     * and RFC 4193 (IPv6 addresses). That is, it reports whether ip is in 10.0.0.0/8,
     * 172.16.0.0/12, 192.168.0.0/16, or fc00::/7.
     */
    isPrivate(): boolean;

    /**
     * Returns true if it is a multicast address.
     */
    isMulticast(): boolean;

    /**
     * Returns true if it is a link-local multicast address.
     */
    isLinkLocalMulticast(): boolean;

    /**
     * Returns true if it is an IPv6 interface-local multicast address.
     */
    isInterfaceLocalMulticast(): boolean;

    /**
     * Returns true if it is a link-local unicast address.
     */
    isLinkLocalUnicast(): boolean;

    /**
     * Returns true if it is a global unicast address.
     */
    isGlobalUnicast(): boolean;

    /**
     * Returns true if it is a documentation address.
     *
     * [RFC 5737: IPv4 Address Blocks Reserved for Documentation](https://datatracker.ietf.org/doc/html/rfc5737)
     * [RFC 3849: IPv6 Address Prefix Reserved for Documentation](https://datatracker.ietf.org/doc/html/rfc3849)
     */
    isDocumentation(): boolean;

    /**
     * Returns true if it is a discard address.
     *
     * [RFC 6666: A Discard Prefix for IPv6](https://datatracker.ietf.org/doc/html/rfc6666)
     */
    isDiscard(): boolean;

    /**
     * Returns true if this address appears to be globally reachable.
     */
    isGlobalReachable(): boolean;
}
