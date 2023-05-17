import { AddressError } from "./error";
import { Address } from "./ip";
import { Address4 } from "./ipv4";
import { Address6 } from "./ipv6";
import * as util from "./util";

/**
 * Prefix is an IP address prefix (CIDR) representing an IP network or an address
 * block.
 *
 * See also: {@link https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing}
 */
export class Prefix {
    private address: Address;
    private len: number;

    /**
     * Constructs a new prefix.
     *
     * @param address The IP address
     * @param bits The count of consecutive leading 1-bits (from left to right)
     *        in the network mask
     *
     * @throws AddressError
     */
    constructor(address: Address, len: number) {
        // Ensure prefix length has a valid range for the address.
        if (len < 0 || len > address.bits()) {
            throw new AddressError(`prefix length out of range: ${len}`);
        }

        this.address = address;
        this.len = len;
    }

    toString(): string {
        return `${this.address.toString()}/${this.len}`;
    }

    /**
     * Returns the IP address in the CIDR notation.
     *
     * @returns
     */
    ip(): Address {
        return this.address;
    }

    /**
     * Returns the first IP address in the range.
     *
     * @returns
     */
    firstIP(): Address {
        if (this.len === this.address.bits()) {
            return this.address;
        }

        const bytesKeep = (this.len / 8) | 0;
        const bitsKeep = this.len % 8;
        const octets = this.address.bytesCloned();

        for (let i = bytesKeep; i < octets.length; i++) {
            if (i === bytesKeep && bitsKeep > 0) {
                octets[i] = octets[i] & (~(0xFF >> bitsKeep));
            } else {
                octets[i] = 0;
            }
        }

        if (this.address instanceof Address4) {
            return Address4.fromBytes(octets);
        }

        return Address6.fromBytes(octets);
    }

    /**
     * Returns the prefix length.
     *
     * @returns
     */
    length(): number {
        return this.len;
    }

    /**
     * Reports whether the prefix contains exactly one IP address.
     *
     * @returns
     */
    isSingleIP(): boolean {
        return this.len === this.address.bits();
    }

    /**
     * Returnss prefix in its canonical form, with bits of ip() not in bits() masked off.
     */
    toMasked(): Prefix {
        return new Prefix(this.firstIP(), this.len);
    }

    /**
     * Checkes whether the network includes the ip.
     *
     * Rules:
     *  - An IPv4 address will not match an IPv6 prefix.
     *  - A v4-mapped or v4 translated IPv6 address will not match an IPv4 prefix.
     *  - A zero-value IP will not match any prefix.
     *  - If provided ip has an IPv6 zone, this function returns false, because
     *    IP prefixes strip zones.
     *
     * @param ip
     * @returns
     */
    contains(ip: Address): boolean {
        if (ip.zone() !== "") {
            return false;
        }

        // Ensure they are same type of addresses (i.e. v4 is 32, v6 is 128)
        if (this.address.bits() !== ip.bits()) {
            return false;
        }

        const prefixBytes = this.address.bytes();
        const ipBytes = ip.bytes();
        const byte_num = this.len / 8;
        const bit_num = this.len % 8;

        // Check leading bytes
        if (!util.compareNumberArray(prefixBytes, ipBytes, 0, byte_num)) {
            return false;
        }

        // Check leading bits in the last byte that matters
        if (bit_num > 0) {
            return (prefixBytes[byte_num] ^ ipBytes[byte_num]) >> (8 - bit_num) === 0;
        }

        return true;
    }

    /**
     * Tries to convert the text to a Prefix object.
     *
     * @param s
     * @returns
     */
    static parse(s: string): Prefix {
        const i = s.lastIndexOf("/");
        if (i <= 0) {
            throw new AddressError(`malformed prefix: "/" not found`);
        }

        const p1 = s.substring(0, i);
        const ip: Address = p1.indexOf(":") < 0 ? Address4.parse(p1) : Address6.parse(p1);

        const p2 = s.substring(i + 1);
        if (!/^(0|[1-9][0-9]{0,2})$/.test(p2)) {
            throw new AddressError(`malformed prefix: "${p2}: is not a valid number`);
        }

        return new Prefix(ip, parseInt(p2));
    }
}
