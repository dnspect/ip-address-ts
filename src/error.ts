/**
 * Represent errors occur on parsing and manipulating IP addresses.
 */
export class AddressError extends Error {
    parseMessage?: string;

    constructor(message: string, parseMessage?: string) {
        super(message);

        this.name = "AddressError";

        if (parseMessage !== null) {
            this.parseMessage = parseMessage;
        }
    }
}
