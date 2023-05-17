import { AddressError } from "./error";
import { Address4 } from "./ipv4";
import { expect, use } from "chai";
import chaibytes from "chai-bytes";

use(chaibytes);

describe("test toString()", () => {
    it("should return canonical text", () => {
        expect(Address4.fromBytes(new Uint8Array([203, 0, 113, 1])).toString()).to.equal("203.0.113.1");
    });
});

describe("test fromArpa()", () => {
    it("should throw error", () => {
        expect(() => Address4.fromArpa("")).to.throw(AddressError, "invalid in-addr.arpa. address");
        expect(() => Address4.fromArpa("1.0.0.127.in-addr.arpa")).to.throw(AddressError, "invalid in-addr.arpa. address");
    });

    it("should return address", () => {
        expect(Address4.fromArpa("1.0.0.127.in-addr.arpa.").toString()).to.equal("127.0.0.1");
        expect(Address4.fromArpa("1.0.0.127.").toString()).to.equal("127.0.0.1");
    });
});

describe("test toArpa()", () => {
    it("should return in-addr.arpa. address", () => {
        expect(Address4.parse("127.0.0.1").toArpa()).to.equal("1.0.0.127.in-addr.arpa.");
        expect(Address4.fromArpa("1.0.0.127.").toArpa({ omitSuffix: true })).to.equal("1.0.0.127");
    });
});

describe("test fromBytes()", () => {
    it("should throw error", () => {
        expect(() => Address4.fromBytes(new Uint8Array(0))).to.throw(AddressError, "invalid number of bytes");
        expect(() => Address4.fromBytes(new Uint8Array(3))).to.throw(AddressError, "invalid number of bytes");
    });

    it("should return address", () => {
        expect(Address4.fromBytes(new Uint8Array(4)).toString()).to.equal("0.0.0.0");
        expect(Address4.fromBytes(new Uint8Array([255, 255, 255, 255])).toString()).to.equal("255.255.255.255");
        expect(Address4.fromBytes(new Uint8Array([255, 255, 255, 256])).toString()).to.equal("255.255.255.0");
    });
});

describe("test bytes()", () => {
    it("should return bytes", () => {
        expect(Address4.parse("0.0.0.0").bytes()).to.equalBytes(new Uint8Array([0, 0, 0, 0]));
        expect(Address4.parse("255.255.255.255").bytes()).to.equalBytes(new Uint8Array([255, 255, 255, 255]));
    });
});

describe("test fromHex()", () => {
    it("should throw error", () => {
        expect(() => Address4.fromHex("")).to.throw(AddressError, "invalid IPv4 hex: ");
        expect(() => Address4.fromHex("abcdwxyz")).to.throw(AddressError, "invalid IPv4 hex: abcdwxyz");
    });

    it("should return address", () => {
        expect(Address4.fromHex("7f000001").toString()).to.equal("127.0.0.1");
        expect(Address4.fromHex("0x7f000001").toString()).to.equal("127.0.0.1");
        expect(Address4.fromHex("7f.00.00.01").toString()).to.equal("127.0.0.1");
        expect(Address4.fromHex("7f.0.0.1").toString()).to.equal("127.0.0.1");
    });
});

describe("test toHex()", () => {
    it("should return hex string", () => {
        expect(Address4.parse("0.0.0.0").toHex()).to.equal("00.00.00.00");
        expect(Address4.parse("127.0.0.1").toHex()).to.equal("7f.00.00.01");
        expect(Address4.parse("255.255.255.255").toHex()).to.equal("ff.ff.ff.ff");
    });
});

describe("test fromInteger()", () => {
    it("should throw error", () => {
        expect(() => Address4.fromInteger(-1)).to.throw(AddressError, "invalid IPv4 integer: -1");
        expect(() => Address4.fromInteger(4294967295 + 1)).to.throw(AddressError, "invalid IPv4 integer: 4294967296");
    });

    it("should return address", () => {
        expect(Address4.fromInteger(0).toString()).to.equal("0.0.0.0");
        expect(Address4.fromInteger(4294967295).toString()).to.equal("255.255.255.255");
    });
});

describe("test toInteger()", () => {
    it("should return integer", () => {
        expect(Address4.fromInteger(0).toInteger()).to.equal(0);
        expect(Address4.fromInteger(4294967295).toInteger()).to.equal(4294967295);
    });
});

describe("test to16BitGroups()", () => {
    it("should return 16-bit groups", () => {
        let bitGroups = Address4.parse("0.0.0.0").to16BitGroups();
        expect(bitGroups[0]).to.equal(0x0);
        expect(bitGroups[1]).to.equal(0x0);

        bitGroups = Address4.parse("255.255.255.255").to16BitGroups();
        expect(bitGroups[0]).to.equal(0xffff);
        expect(bitGroups[1]).to.equal(0xffff);
    });
});

describe("test toBinaryString()", () => {
    it("should return zero-padded base-2 string", () => {
        expect(Address4.parse("0.0.0.0").toBinaryString()).to.equal("00000000000000000000000000000000");
        expect(Address4.parse("255.255.255.255").toBinaryString()).to.equal("11111111111111111111111111111111");
    });
});

describe("test isUnspecified()", () => {
    it("should be unspecified", () => {
        expect(Address4.parse("0.0.0.0").isUnspecified()).to.true;
    });
    it("should not be unspecified", () => {
        expect(Address4.parse("0.0.0.1").isUnspecified()).to.false;
    });
});
