
import * as util from "./util";
import { Address4 } from "./ipv4";
import { AddressError } from "./error";
import { Address } from "./ip";
import { Prefix } from "./prefix";

/**
 * Number of the bits an IPv6 address consists of.
 */
const BITS = 128;

/**
 * Number of the bytes an IPv6 address consists of.
 */
const BYTES_LEN = 16;

/**
 * Number of fields of IPv6 address's text representation format in full form.
 *
 * An IPv6 address is represented as eight fields of four hexadecimal digits,
 * each field representing 16 bits.
 */
const FIELDS_LEN = 8;

/**
 * Every IPv6 address, except the unspecified address (::), has a "scope",[10] which specifies in
 * which part of the network it is valid.
 */
enum Scope {
    Reserved = "Reserved",
    /**
     * Interface-local scope spans only a single interface on a node, and is useful only for loopback
     * transmission of multicast.
     */
    InterfaceLocal = "Interface local",
    /**
     * Link-local scope spans the same topological region as the corresponding unicast scope.
     */
    LinkLocal = "Link local",
    /**
     * Realm-local scope is defined as larger than link-local, automatically determined by network
     * topology and must not be larger than the following scopes.[14]
     */
    RealmLocal = "Realm local",
    /**
     * Admin-local scope is the smallest scope that must be administratively configured, i.e., not
     * automatically derived from physical connectivity or other, non-multicast-related configuration.
     */
    AdminLocal = "Admin local",
    /**
     * Site-local scope is intended to span a single site belonging to an organization.
     */
    SiteLocal = "Site local",
    /**
     * Organization-local scope is intended to span all sites belonging to a single organization.
     */
    OrganizationLocal = "Organization local",
    /**
     * Global scope spans all reachable nodes on the internet - it is unbounded.
     */
    Global = "Global",

    /**
     * Unassigned or unknown scope.
     */
    Unknown = "",
}

/**
 * Maps IPv6 address scope values to the {Scope} enum variants.
 */
const SCOPE_MAP: { [value: number]: Scope | undefined } = {
    0: Scope.Reserved,
    1: Scope.InterfaceLocal,
    2: Scope.LinkLocal,
    3: Scope.RealmLocal,
    4: Scope.AdminLocal,
    5: Scope.SiteLocal,
    8: Scope.OrganizationLocal,
    14: Scope.Global,
    15: Scope.Reserved,
} as const;

/**
 * Represents IPv6 address types.
 *
 * @fixme create subnets as constant prefixes.
 */
const TYPES: { [subnet: string]: string | undefined } = {
    "::/0": "Default route", // https://en.wikipedia.org/wiki/Default_route
    "::/128": "Unspecified address",
    "::1/128": "Loopback address",
    "::ffff:0:0/96": "IPv4-mapped address",
    "::ffff:0:0:0/96": "IPv4 translated address",
    "64:ff9b::/96": "IPv4/IPv6 translation", // https://datatracker.ietf.org/doc/html/rfc6052
    "64:ff9b:1::/48": "IPv4/IPv6 translation", // https://datatracker.ietf.org/doc/html/rfc8215
    "100::/64": "Discard prefix", // https://datatracker.ietf.org/doc/html/rfc6666
    "2001:0000::/32": "Teredo tunneling", // https://datatracker.ietf.org/doc/html/rfc4680
    "2001:20::/28": "ORCHIDv2", // https://datatracker.ietf.org/doc/html/rfc7343
    "2001:db8::/32": "Addresses used in documentation and example source code", // https://datatracker.ietf.org/doc/html/rfc3849
    "2002::/16": "The 6to4 addressing scheme (deprecated)", // https://datatracker.ietf.org/doc/html/rfc7526
    "fc00::/7": "Unique local address", // https://datatracker.ietf.org/doc/html/rfc4193
    "fe80::/10": "Link-local address",
    "ff00::/8": "Multicast",
} as const;

/**
 * A regular expression that matches explicit incorrect IPv6 address.
 */
const RE_BAD_ADDRESS = /([0-9a-f]{5,}|:{3,}|[^:]:$|^:[^:]|::0+:|::0+$|:0+::|^0+::|[^0-9a-f:]+)/gi;

/**
 * A regular expression that matches an IPv6 arpa address.
 */
const RE_ARPA = /^(([0-9a-f]\.){32})(ip6\.arpa\.)?$/i;

/**
 * Creates a new IPv6 address prefix.
 *
 * @param address
 * @param len
 * @returns
 */
function newPrefix(address: Address6, len: number) {
    return new Prefix(address, len);
}

/**
 * Returns the canonical text representation format of the address.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc5952#section-4
 *
 * @param fields the eight 16-bit fields
 * @returns
 */
function normalize(data: Uint8Array): string {
    let zeros = 0; // Count the consecutive all-zeros.
    let maxSize = 0; // The size of leftmost consecutive all-zero fields
    let rangeStart = -1; // The start pos of the leftmost range of consecutive all-zero fields
    const fields = new Uint16Array(FIELDS_LEN);

    for (let i = 0; i < FIELDS_LEN; i++) {
        fields[i] = (data[i * 2] << 8) + data[i * 2 + 1];

        if (fields[i] === 0) {
            zeros++;
        } else if (zeros > 0) {
            // Ignore single all-zero field
            // https://datatracker.ietf.org/doc/html/rfc5952#section-4.2.2
            if (zeros > 1) {
                if (zeros > maxSize) {
                    maxSize = zeros;
                    rangeStart = i - zeros;
                }
            }

            zeros = 0;
        }
    }

    // Deal with address ends with consecutive zeroes
    if (zeros > maxSize) {
        maxSize = zeros;
        rangeStart = FIELDS_LEN - zeros;
    }

    // Find all zeros (UNSPECIFIED address)
    if (maxSize === FIELDS_LEN) {
        return "::";
    }

    const groups = [];
    for (let i = 0; i < FIELDS_LEN; i++) {
        if (maxSize > 0 && i === rangeStart) {
            groups.push(i === 0 || rangeStart + maxSize === FIELDS_LEN ? ":" : "");
            i = rangeStart + maxSize - 1; // fast forward to skip elements in the range
        } else {
            groups.push(fields[i].toString(16));
        }
    }

    return groups.join(":");
}

/**
 * An IPv6 address.
 */
export class Address6 implements Address {
    private octets: Uint8Array;
    private address: string; // The raw textual
    private z = ""; // Scoped addressing zone
    private normalized: boolean | null = null;
    private address4: Address4 | null = null;

    /**
     * Constructs an Address6 object.
     *
     * @param octets The 16-bytes binary data.
     * @param address The original textual form of the address.
     * @param zone
     * @param address4 The IPv4 address, usually provided when creating a 4in6 address.
     *
     * @throws AddressError
     */
    private constructor(octets: Uint8Array, address: string | null, zone: string | null, address4: Address4 | null) {
        if (octets.length !== 16) {
            throw new AddressError(`invalid number of bytes: ${octets.byteLength} ${octets.length}`);
        }

        this.octets = octets;
        this.z = zone || "";

        if (address) {
            this.address = address;
        } else {
            this.address = normalize(octets);
            this.normalized = true;
        }

        this.address4 = address4;
    }

    /**
     * Try parse a 4in6 IPv6 address textual that contains the IPv4 part in dotted
     * decimal notation.
     *
     * If it is a 4in6 address, the dotted decimal notation will be normalized by
     * replacing it with two 16-bit fields.
     *
     * @param address A textual address
     * @returns
     */
    private static parse4in6(address: string): [Address4 | null, string | null] {
        const dotPos = address.indexOf(".");
        // Not a 4in6 at all
        if (dotPos <= 0) {
            return [null, null];
        }

        const i = address.lastIndexOf(":");
        // The dotted notation should be the last part of the text.
        if (i >= dotPos) {
            return [null, null];
        }

        const lastPart = address.substring(i + 1);
        try {
            const address4 = Address4.parse(lastPart);
            const fields = address4.to16BitGroups();
            // Replace dotted decimal notation with two 16-bit fields
            const normalizedAddress = `${address.substring(0, i + 1)}${util.hex(fields[0])}:${util.hex(fields[1])}`;
            return [address4, normalizedAddress];
        } catch (e) {
            return [null, null];
        }
    }

    /**
     * Returns the original form of the address when it is created.
     *
     * @returns
     */
    raw(): string {
        return this.address;
    }

    /**
     * Returns the number of bits of the address.
     *
     * @returns
     */
    bits(): number {
        return BITS;
    }

    /**
     * Returns IPv6 scoped addressing zone, if any.
     *
     * @returns
     */
    zone(): string {
        return this.z;
    }

    /**
     * Returns the scope of the address.
     *
     * @returns
     */
    getScope(): Scope {
        if (this.octets[0] !== 0xFF) {
            return Scope.Unknown;
        }

        return SCOPE_MAP[this.octets[1] & 0xF] || Scope.Unknown;
    }

    /**
     * Returns the type of the address.
     *
     * @returns
     */
    getType(): string {
        for (const subnet of Object.keys(TYPES)) {
            const prefix = Prefix.parse(subnet);
            if (prefix.contains(this)) {
                return TYPES[subnet] as string;
            }
        }

        return "Global";
    }

    /**
     * Returns the reversed ip6.arpa form of the address.
     *
     * @param options
     * @returns
     */
    toArpa(options?: util.ArpaOptions): string {
        const parts = new Array<string>(32);
        this.octets.reverse().forEach((v, i) => {
            parts[i * 2] = (v & 0xF).toString(16);
            parts[i * 2 + 1] = (v >> 4 & 0xF).toString(16);
        });

        const reversed = parts.join(".");
        if (options?.omitSuffix) {
            return reversed;
        }

        return `${reversed}.ip6.arpa.`;
    }

    /**
     * Returns the complete form of the IPv6 address.
     *
     * @returns
     */
    toHex(): string {
        const groups = new Array<string>(FIELDS_LEN);
        for (let i = 0; i < FIELDS_LEN; i++) {
            groups[i] = util.hex(((this.octets[i * 2] << 8) + this.octets[i * 2 + 1]), 4);
        }
        return groups.join(":");
    }

    /**
     * Returns the canonical text representation format of IPv6 addresses.
     *
     * @returns
     */
    toString(): string {
        if (this.normalized) {
            return this.address;
        }

        return normalize(this.octets);
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
        return this.octets.slice();
    }

    /**
     * Converts the underlying data to a 16-bits array.
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
        return this.octets.reduce((str, v) => str + v.toString(2).padStart(8, '0'), '');
    }

    /**
     * @override
     */
    isIPv4(): boolean {
        return false;
    }

    /**
     * @override
     */
    isIPv6(): boolean {
        return true;
    }

    /**
     * Converts this address to an IPv4 address if it's an IPv4-mapped address, as defined in
     * [IETF RFC 4291 section 2.5.5.2], otherwise returns `null`.
     *
     * @returns
     */
    toIPv4Mapped(): Address4 | null {
        if (IPV4_MAPPED_PREFIX.contains(this)) {
            if (this.address4 === null) {
                this.address4 = Address4.fromBytes(this.octets.slice(12, 16));
            }
            return this.address4;
        }
        return null;
    }

    /**
     * Converts this address to an IPv4 address if it is either, 4in6 address, an IPv4-compatible
     * address as defined in [IETF RFC 4291 section 2.5.5.1], an IPv4 translated address, or an
     * IPv4-mapped address as defined in [IETF RFC 4291 section 2.5.5.2], otherwise returns `null`.
     *
     * Note that this will also return an IPv4 address for the IPv6 unspecified address `::` and
     * the loopback address `::1` because they are in the IPv4-compatible prefix. Consider to use
     * `toIPv4Mapped()` to avoid this.
     *
     * @returns
     */
    toIPv4(): Address4 | null {
        if (this.address4 === null) {
            if (this.isLoopback()) {
                this.address4 = Address4.fromBytes(new Uint8Array([127, 0, 0, 1]));
            } else if (IPV4_COMPATIBLE_PREFIX.contains(this) ||
                IPV4_MAPPED_PREFIX.contains(this) ||
                IPV4_TRANSLATED_PREFIX.contains(this)
            ) {
                this.address4 = Address4.fromBytes(this.octets.slice(12, 16));
            }
        }
        return this.address4;
    }

    /**
     * Returns the v4-in-v6 form representation of the address where the IPv4
     * part is formatted in dotted decimal notation.
     *
     * @returns
     */
    to4in6(): string {
        // Copy the underlying data
        const newData = this.bytesCloned();
        // Use the last 4 bytes to create a temp v4 address.
        const v4 = Address4.fromBytes(newData.slice(12, 16));
        // Avoid the last two fields (4 bytes) get shortened when they are zeros
        newData[newData.length - 4] = 0xFF;
        newData[newData.length - 3] = 0xFF;
        newData[newData.length - 2] = 0xFF;
        newData[newData.length - 1] = 0xFF;

        const output = Address6.fromBytes(newData).toString();

        // Replace the trailing "ffff:ffff" with the IPv4 canonical text
        return output.substring(0, output.length - 9) + v4.toString();
    }

    /**
     * Returns true if the address is in the canonical form, false otherwise.
     *
     * @returns
     */
    isCanonical(): boolean {
        if (this.normalized === null) {
            const c = this.toString();
            this.normalized = this.address === (this.z === "" ? c : `${c}%${this.z}`);
        }

        return this.normalized;
    }

    /**
     * Returns true if the address is a unspecified address, false otherwise.
     *
     * @returns
     */
    isUnspecified(): boolean {
        return UNSPECIFIED.contains(this);
    }

    /**
     * Returns true if the address is a link local address, false otherwise.
     *
     * @returns
     */
    isLinkLocal(): boolean {
        return LINK_LOCAL_PREFIX.contains(this);
    }

    /**
     * Returns true if the address is a multicast address, false otherwise
     *
     * @returns {boolean}
     */
    isMulticast(): boolean {
        return MULTICAST_PREFIX.contains(this);
    }

    /**
     * Returns true if the address is a loopback address, false otherwise
     *
     * @returns {boolean}
     */
    isLoopback(): boolean {
        return LOOPBACK_PREFIX.contains(this);
    }

    /**
     * Checks if the given string is a valid IPv6 address.
     *
     * @param address a textual address
     * @returns
     */
    static isValid(address: string): boolean {
        try {
            // eslint-disable-next-line no-new
            Address6.parse(address);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Try parses literal IPv6 address to Uint16 array.
     *
     * @param raw An textual address
     * @returns
     *
     * @throws AddressError
     */
    static parse(raw: string): Address6 {
        let address = raw;
        let zone = "";

        // Extract zone part
        const zoneStart = address.indexOf('%');
        if (zoneStart > 0) {
            zone = address.substring(zoneStart + 1).trimEnd();
            address = address.substring(0, zoneStart);
            if (address === "::") {
                throw new AddressError(`malformed IPv6 address: unspecified address (::) should not have a scope`);
            }
        }

        // Maybe a 4in6 address, try to parse it
        const [address4, normalizedAddress] = Address6.parse4in6(address);
        if (normalizedAddress) {
            address = normalizedAddress;
        }

        const badMatch = address.match(RE_BAD_ADDRESS);
        if (badMatch) {
            throw new AddressError(`malformed IPv6 address: "${badMatch[0]}" is unexpected`);
        }

        const groups = new Array<number>();

        const halves = address.split("::");
        if (halves.length === 2) { // find "::" in the address
            let first = halves[0].split(":");
            let last = halves[1].split(":");

            if (first.length === 1 && first[0] === "") {
                first = [];
            }

            if (last.length === 1 && last[0] === "") {
                last = [];
            }

            const remaining = FIELDS_LEN - (first.length + last.length);
            if (remaining <= 1) {
                throw new AddressError(`malformed IPv6 address: "::" should represent at least two consecutive all-zero fields`);
            }

            for (const part of first) {
                const n = parseInt(part, 16);
                groups.push(n >> 8, n & 0xFF);
            }
            for (let i = 0; i < remaining; i++) {
                groups.push(0, 0);
            }
            for (const part of last) {
                const n = parseInt(part, 16);
                groups.push(n >> 8, n & 0xFF);
            }
        } else if (halves.length === 1) { // no "::" in the address
            const parts = address.split(":");
            if (parts.length !== FIELDS_LEN) {
                throw new AddressError(`malformed IPv6 address: ${raw}`);
            }

            for (const part of parts) {
                const n = parseInt(part, 16);
                groups.push(n >> 8, n & 0xFF);
            }
        } else {
            throw new AddressError(`malformed IPv6 address: too many "::" groups found`);
        }

        return new Address6(new Uint8Array(groups), raw, zone, address4);
    }

    /**
     * Creates an IPv4-mapped IPv6 address directly from an IPv4 address text.
     *
     * @param address - An IPv4 address text
     * @returns
     *
     * @throws AddressError
     */
    static fromAddress4(address: string): Address6 {
        return Address6.mappedFrom(Address4.parse(address));
    }

    /**
     * Converts a byte array to an Address6 object.
     *
     * @returns
     */
    static fromBytes(bytes: Uint8Array): Address6 {
        return new Address6(bytes, null, null, null);
    }

    /**
     * Returns an address from the 16-bit fields.
     *
     * @param fields
     * @returns
     *
     * @throws AddressError
     */
    static from16BitFields(fields: Uint16Array): Address6 {
        if (fields.length !== FIELDS_LEN) {
            throw new AddressError(`invalid number of 16-bit fields`);
        }
        return new Address6(util.uint16ArrayToUint8Array(fields), null, null, null);
    }

    /**
     * Returns an address from ip6.arpa. form.
     *
     * @param arpa - an ip6.arpa. form address
     * @returns
     *
     * @throws AddressError
     *
     * @example
     * ```
     * const address = Address6.fromArpa("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.");
     * address.toString(); // 2001:db8::1
     * ```
     */
    static fromArpa(arpa: string): Address6 {
        const match = arpa.match(RE_ARPA);
        if (!match) {
            throw new AddressError("invalid ip6.arpa. address");
        }

        // Note that parts contains a leading dot.
        const parts = match[1].split(".").reverse();
        const data = new Uint8Array(BYTES_LEN);

        for (let i = 0; i < data.length; i++) {
            data[i] = (parseInt(parts[i * 2 + 1], 16) << 4) + parseInt(parts[i * 2 + 2], 16);
        }

        return Address6.fromBytes(data);
    }

    /**
     * Returns the IPv4-mapped IPv6 address.
     *
     * Address block - ::ffff:0:0/96
     *
     * @returns
     */
    static mappedFrom(address4: Address4): Address6 {
        const data = IPV4_MAPPED_PREFIX.ip().bytesCloned();
        const value = address4.bytes();
        data.set(value, data.length - 4);

        return new Address6(data, null, null, address4);
    }

    /**
     * Returns the IPv4 translated IPv6 address.
     *
     * Address block - ::ffff:0:0:0/96
     *
     * @returns
     */
    static translatedFrom(address4: Address4): Address6 {
        const data = IPV4_TRANSLATED_PREFIX.ip().bytesCloned();
        const value = address4.bytes();
        data.set(value, data.length - 4);
        return new Address6(data, null, null, address4);
    }
}

/**
 * The unspecified address in prefix form.
 */
const UNSPECIFIED = newPrefix(Address6.parse("::"), 128);

/**
 * The loopback address prefix.
 */
const LOOPBACK_PREFIX = newPrefix(Address6.parse("::1"), 128);

/**
 * The link-local address prefix.
 */
const LINK_LOCAL_PREFIX = newPrefix(Address6.parse("fe80::"), 64);

/**
 * The multicast address prefix.
 */
const MULTICAST_PREFIX = newPrefix(Address6.parse("ff00::"), 8);

/**
 * The first 6 16-bit fields of an IPv4-mapped IPv6 address.
 *
 * IPv4-mapped address prefix is ::ffff:0:0/96
 */
const IPV4_MAPPED_PREFIX = newPrefix(Address6.parse("::ffff:0:0"), 96);

/**
 * The first 6 16-bit fields of an IPv4 translated IPv6 address.
 *
 * IPv4 translated address prefix is ::ffff:0:0:0/96
 */
const IPV4_TRANSLATED_PREFIX = newPrefix(Address6.parse("::ffff:0:0:0"), 96);

/**
 * The "IPv4-Compatible IPv6 address" was defined to assist in the IPv6
 * transition.  The format of the "IPv4-Compatible IPv6 address" is as
 * follows:
 *
 * ```
 * |                80 bits               | 16 |      32 bits        |
 * +--------------------------------------+--------------------------+
 * |0000..............................0000|0000|    IPv4 address     |
 * +--------------------------------------+----+---------------------+
 * ```
 *
 * Note: The IPv4 address used in the "IPv4-Compatible IPv6 address" must be a globally-unique IPv4
 * unicast address.
 *
 * The "IPv4-Compatible IPv6 address" is now deprecated because the current IPv6 transition mechanisms
 * no longer use these addresses.  New or updated implementations are not required to support this
 * address type.
 */
const IPV4_COMPATIBLE_PREFIX = newPrefix(Address6.parse("::"), 96);
