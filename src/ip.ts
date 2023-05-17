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
     * Returns true if it is an unspecified address, false otherwise.
     */
    isUnspecified(): boolean;

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
}
