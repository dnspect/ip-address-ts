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

    isUnspecified(): boolean {
        return util.compareNumberArray(this.octets, UNSPECIFIED);
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
     * Returns a zero-padded base-2 string representation of the address.
     *
     * @returns
     */
    toBinaryString(): string {
        const c = [];
        for (const n of this.octets) {
            c.push(n.toString(2).padStart(8, "0"));
        }
        return c.join("");
    }

    /**
     * Checks if the textual address is a valid IPv4 address.
     *
     * @param address
     * @returns
     */
    static isValid(address: string): boolean {
        try {
            Address4.parse(address);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Parses a v4 address
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
