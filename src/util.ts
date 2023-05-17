/* eslint-disable no-param-reassign */

export interface ArpaOptions {
    omitSuffix?: boolean;
}

/**
 * Converts the number to a hex string.
 *
 * @param n
 * @returns
 */
export function hex(n: number, pad = 0, prefix = false): string {
    const x = n.toString(16).padStart(pad, '0');
    return prefix ? `0x${x}` : x;
}

/**
 * Compares two uint array's elements in the given range. Returns true if all
 * the elements in the range are equal, returns false otherwise.
 *
 * @param a
 * @param b
 * @param start The start of the specified portion of the array.
 * @param end The end of the specified portion of the array. This is exclusive
 *            of the element at the index 'end'.
 * @returns
 */
export function compareNumberArray(a: Uint8Array | Uint16Array, b: Uint8Array | Uint16Array, start = 0, end?: number): boolean {
    if (end) {
        if (a.length < end || b.length < end) {
            return false;
        }

        if (start > end) {
            return false;
        }

    } else {
        if (a.length !== b.length) {
            return false;
        }
        end = a.length;
    }

    for (let i = start; i < end; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }

    return true;
}


/**
 * Converts an Uint8Array to an Uint16Array.
 *
 * @param a
 * @returns
 *
 * @throws Error length of the Uint8Array should be even
 */
export function uint8ArrayToUint16Array(a: Uint8Array): Uint16Array {
    if (a.length % 2 !== 0) {
        throw new Error("length of the Uint8Array should be even");
    }

    const output = new Uint16Array(a.length / 2);
    for (let i = 0; i < a.length; i += 2) {
        output[i / 2] = (a[i] << 8) + a[i + 1];
    }
    return output;
}

/**
 *
 * Converts an Uint16Array to an Uint8Array.
 *
 * @param a
 * @returns
 */
export function uint16ArrayToUint8Array(a: Uint16Array): Uint8Array {
    const bytes = new Uint8Array(a.length * 2);
    a.forEach((n, i) => {
        bytes[i * 2] = n >> 8;
        bytes[i * 2 + 1] = n & 0xFF;
    });
    return bytes;
}
