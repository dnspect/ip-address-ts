import { AddressError } from "./error";
import { Address } from "./ip";
import { Address4 } from "./ipv4";
import { Address6 } from "./ipv6";

export { AddressError } from "./error";
export { Address } from "./ip";
export { Address4 } from "./ipv4";
export { Address6 } from "./ipv6";
export { Prefix } from "./prefix";
export * from "./util";

/**
 * Checks if the given string is a valid IP address (either IPv4 or IPv6).
 *
 * @param address The string to check
 * @returns True if the address is a valid IP address.
 */
export function validate(address: string): boolean {
    return Address4.validate(address) || Address6.validate(address);
}

/**
 * Parses an IP address.
 *
 * @param address The string to parse
 * @returns An IP address
 *
 * @throws AddressError
 */
export function parse(address: string): Address {
    try {
        return Address4.parse(address);
    } catch (_e) {
        // No-op
    }

    try {
        return Address6.parse(address);
    } catch (_e) {
        // No-op
    }

    throw new AddressError(`invalid IP address: ${address}`);
}
