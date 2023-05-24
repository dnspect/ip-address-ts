import * as util from "./util";
import { AddressError } from "./error";
import { Address } from "./ip";

/**
 * Number of the bits an IPv4 address consists of.
 */
const BITS = 32;

/**
 * Number of bytes of IPv4 address consists of.
 */
const BYTES_LEN = 4;

/**
 * The underlying data of the unspecified IPv4 address.
 */
const UNSPECIFIED = new Uint8Array([0, 0, 0, 0]);

/**
 * A special broadcast address of the zero network.
 */
const BROADCAST = new Uint8Array([255, 255, 255, 255]);

/**
 * Regular pattern to match a valid IPv4 address string.
 */
const RE_ADDRESS =
    /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/;

/**
 * Regular pattern to match a valid IPv4 arpa address.
 */
const RE_ARPA =
    /^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){4})(in-addr\.arpa\.)?$/i;

/**
 * Regular pattern to match a valid IPv4 address in hexadecimal string.
 */
const RE_ADDRESS_HEX = /^(0x)?([0-9a-f]{1,8})$/i;

/**
 * Regular pattern to match a valid IPv4 address in hexadecimal string.
 */
const RE_ADDRESS_HEX_DOTTED = /^([0-9a-f]{1,2})\.([0-9a-f]{1,2})\.([0-9a-f]{1,2})\.([0-9a-f]{1,2})$/i;

/**
 * An IPv4 address.
 */
export class Address4 implements Address {
    private address: string; // An IPv4 address string
    private octets: Uint8Array;

    /**
     * Constructs a new Address4 object.
     *
     * @param octets The octet array representing the binary data.
     * @param address The original textual of the address.
     */
    private constructor(octets: Uint8Array, address?: string) {
        if (octets.length !== BYTES_LEN) {
            throw new AddressError("invalid number of bytes");
        }

        this.octets = octets;
        this.address = address || octets.join('.');
    }

    /**
     * Returns the original form of the address when it is created.
     *
     * @returns
     */
    raw(): string {
        return this.address;
    }

    isIPv4(): boolean {
        return true;
    }

    isIPv6(): boolean {
        return false;
    }

    bits(): number {
        return BITS;
    }

    /**
     * Returns the canonical text representation format of the address.
     *
     * @returns
     */
    toString(): string {
        return this.octets.join(".");
    }

    /**
     * Returns empty always as IPv6 address does not have the IPv6 scoped addressing zone.
     *
     * @returns
     */
    zone(): string {
        return "";
    }

    /**
     * Returns the reversed ip6.arpa form of the address
     *
     * @param options
     * @returns
     */
    toArpa(options?: util.ArpaOptions): string {
        const reversed = this.octets.reverse().join(".");
        if (options?.omitSuffix) {
            return reversed;
        }
        return `${reversed}.in-addr.arpa.`;
    }

    /**
     * Converts an IPv4 address object to an integer.
     *
     * @returns
     */
    toInteger(): number {
        return this.octets.reduce((n, octet) => {
            return (n << 8) + octet;
        }, 0) >>> 0;
    }

    /**
     * Returns the hex string representation.
     *
     * @returns
     */
    toHex(): string {
        const c = new Array<string>(4);
        this.octets.forEach((n, i) => {
            c[i] = util.hex(n, 2);
        });

        return c.join(".");
    }

    /**
     * Returns a reference to the underlying data.
     *
     * @returns
     */
    bytes(): Uint8Array {
        return this.octets;
    }

    /**
     * Returns a clone of the underlying data.
     *
     * @returns
     */
    bytesCloned(): Uint8Array {
        return new Uint8Array(this.octets.buffer);
    }

    /**
     * Converts the underlying data to a 16-bit array.
     *
     * @returns
     */
    to16BitGroups(): Uint16Array {
        return util.uint8ArrayToUint16Array(this.octets);
    }

    /**
     * @override
     */
    toBinaryString(): string {
        const c = [];
        for (const n of this.octets) {
            c.push(n.toString(2).padStart(8, "0"));
        }
        return c.join("");
    }

    /**
     * @override
     */
    isUnspecified(): boolean {
        return util.compareNumberArray(this.octets, UNSPECIFIED);
    }

    /**
     * @override
     */
    isLoopback(): boolean {
        // Requirements for Internet Hosts -- Communication Layers (3.2.1.3 Addressing)
        // https://datatracker.ietf.org/doc/html/rfc1122#section-3.2.1.3
        return this.octets[0] === 127;
    }

    /**
     * @override
     */
    isPrivate(): boolean {
        // RFC 1918 allocates 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 as
        // private IPv4 address subnets.
        return this.octets[0] === 10 ||
            (this.octets[0] === 172 && (this.octets[1] & 0xF0) === 16) ||
            (this.octets[0] === 192 && this.octets[1] === 168);
    }

    /**
     * @override
     */
    isMulticast(): boolean {
        // Host Extensions for IP Multicasting (4. HOST GROUP ADDRESSES)
        // https://datatracker.ietf.org/doc/html/rfc1112#section-4
        return (this.octets[0] & 0xF0) === 0xE0;
    }

    /**
     * @override
     */
    isLinkLocalMulticast(): boolean {
        // IPv4 Multicast Guidelines (4. Local Network Control Block (224.0.0/24))
        // https://datatracker.ietf.org/doc/html/rfc5771#section-4
        return this.octets[0] === 224 && this.octets[1] === 0 && this.octets[2] === 0;
    }

    /**
     * @override
     */
    isInterfaceLocalMulticast(): boolean {
        return false;
    }

    /**
     * @override
     */
    isLinkLocalUnicast(): boolean {
        // Dynamic Configuration of IPv4 Link-Local Addresses
        // https://datatracker.ietf.org/doc/html/rfc3927#section-2.1
        return this.octets[0] === 169 && this.octets[1] === 254;
    }

    /**
     * @override
     */
    isGlobalUnicast(): boolean {
        return !(
            // "This network"
            this.octets[0] === 0 ||
            this.isUnspecified() ||
            this.isLoopback() ||
            this.isMulticast() ||
            this.isLinkLocalUnicast() ||
            this.isPrivate() ||
            util.compareNumberArray(this.octets, BROADCAST)
        );
    }

    /**
     * @override
     */
    isDocumentation(): boolean {
        // https://datatracker.ietf.org/doc/html/rfc5737#section-3
        return (this.octets[0] === 192 && this.octets[1] === 0 && this.octets[2] === 2) ||
            (this.octets[0] === 198 && this.octets[1] === 51 && this.octets[2] === 100) ||
            (this.octets[0] === 203 && this.octets[1] === 0 && this.octets[2] === 113);
    }

    /**
     * @override
     */
    isDiscard(): boolean {
        return false;
    }

    /**
     * @override
     */
    isGlobalReachable(): boolean {
        return this.isGlobalUnicast() && !(
            this.isDocumentation() ||
            this.isDiscard() ||
            this.isShared()
        );
    }

    /**
     * Returns true if this address is part of the Shared Address Space defined in
     * RFC 6598 (100.64.0.0/10).
     */
    isShared(): boolean {
        return this.octets[0] === 100 && ((this.octets[1] & 0xC0) === 0x40);
    }

    /**
     * Checks if the textual address is a valid IPv4 address.
     *
     * @param address
     * @returns
     */
    static validate(address: string): boolean {
        try {
            Address4.parse(address);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Parses a v4 address
     *
     * @throws AddressError
     */
    static parse(address: string): Address4 {
        if (!address.match(RE_ADDRESS)) {
            throw new AddressError(`invalid IPv4 address: ${address}`);
        }

        const groups = address.split(".");
        return new Address4(new Uint8Array(groups.map((part) => parseInt(part, 10))));
    }

    /**
     * Converts a hex string to an IPv4 address object.
     *
     * @param hex - a hex string to convert
     * @returns
     *
     * @throws AddressError
     */
    static fromHex(hex: string): Address4 {
        const bytes = new Uint8Array(BYTES_LEN);

        let match = hex.match(RE_ADDRESS_HEX);
        if (match) {
            const padded = match[2].padStart(BYTES_LEN * 2, "0");
            for (let i = 0; i < BYTES_LEN; i++) {
                const h = padded.slice(i * 2, i * 2 + 2);
                bytes[i] = parseInt(h, 16);
            }
        } else {
            match = hex.match(RE_ADDRESS_HEX_DOTTED);
            if (match) {
                bytes[0] = parseInt(match[1], 16);
                bytes[1] = parseInt(match[2], 16);
                bytes[2] = parseInt(match[3], 16);
                bytes[3] = parseInt(match[4], 16);
            } else {
                throw new AddressError(`invalid IPv4 hex: ${hex}`);
            }
        }

        return new Address4(bytes);
    }

    /**
     * Converts an integer into an IPv4 address object.
     *
     * @param bytes - a byte array to convert
     * @returns
     */
    static fromBytes(bytes: Uint8Array): Address4 {
        return new Address4(bytes);
    }

    /**
     * Converts an integer into an IPv4 address object.
     *
     * @param n - a number to convert
     * @returns
     *
     * @throws AddressError
     */
    static fromInteger(n: number): Address4 {
        if (n < 0 || n > 4294967295) {
            throw new AddressError(`invalid IPv4 integer: ${n}`);
        }

        return new Address4(Uint8Array.from([
            n >>> 24,
            n >> 16 & 255,
            n >> 8 & 255,
            n & 255
        ]));
    }

    /**
     * Returns an address from in-addr.arpa form.
     *
     * @param arpa - An in-addr.arpa. form ipv4 address
     * @returns
     *
     * @throws AddressError
     *
     * @example
     * const address = Address4.fromArpa("1.113.0.203.in-addr.arpa.");
     * address.toString(); // 203.0.113.1
     */
    static fromArpa(arpa: string): Address4 {
        const match = arpa.match(RE_ARPA);
        if (!match) {
            throw new AddressError("invalid in-addr.arpa. address");
        }

        const parts = match[1].split(".").reverse();
        const bytes = new Uint8Array(BYTES_LEN);

        for (let i = 0; i < BYTES_LEN; i++) {
            bytes[i] = parseInt(parts[i + 1]);
        }

        return new Address4(bytes);
    }
}
