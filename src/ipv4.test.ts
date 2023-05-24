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

describe("test isLoopback()", () => {
    it("should be loopback", () => {
        expect(Address4.parse("127.0.0.0").isLoopback()).to.true;
    });
    it("should not be unspecified", () => {
        expect(Address4.parse("126.0.0.0").isLoopback()).to.false;
        expect(Address4.parse("128.0.0.0").isLoopback()).to.false;
    });
});

describe("test isPrivate()", () => {
    it("should be private", () => {
        expect(Address4.parse("10.0.0.0").isPrivate()).to.true;
        expect(Address4.parse("172.16.0.0").isPrivate()).to.true;
        expect(Address4.parse("192.168.0.0").isPrivate()).to.true;
    });
    it("should not be private", () => {
        expect(Address4.parse("9.0.0.0").isPrivate()).to.false;
        expect(Address4.parse("11.0.0.0").isPrivate()).to.false;
    });
});

describe("test isMulticast()", () => {
    it("should be multicast", () => {
        expect(Address4.parse("224.0.0.0").isMulticast()).to.true;
        expect(Address4.parse("239.255.255.255").isMulticast()).to.true;
    });
    it("should not be multicast", () => {
        expect(Address4.parse("223.255.255.255").isMulticast()).to.false;
        expect(Address4.parse("240.0.0.0").isMulticast()).to.false;
    });
});

describe("test isLinkLocalMulticast()", () => {
    it("should be linklocal multicast", () => {
        expect(Address4.parse("224.0.0.0").isLinkLocalMulticast()).to.true;
    });
    it("should not be linklocal multicast", () => {
        expect(Address4.parse("239.255.255.255").isLinkLocalMulticast()).to.false;
    });
});

describe("test isInterfaceLocalMulticast()", () => {
    it("should not be interface linklocal multicast", () => {
        expect(Address4.parse("224.0.0.0").isInterfaceLocalMulticast()).to.false;
        expect(Address4.parse("239.255.255.255").isLinkLocalMulticast()).to.false;
    });
});

describe("test isLinkLocalUnicast()", () => {
    it("should be linklocal unicast", () => {
        expect(Address4.parse("169.254.0.0").isLinkLocalUnicast()).to.true;
        expect(Address4.parse("169.254.255.255").isLinkLocalUnicast()).to.true;
    });
    it("should not be linklocal unicast", () => {
        expect(Address4.parse("169.253.255.255").isLinkLocalUnicast()).to.false;
        expect(Address4.parse("169.255.0.0").isLinkLocalUnicast()).to.false;
    });
});

describe("test isGlobalUnicast()", () => {
    it("should be global unicast", () => {
        expect(Address4.parse("93.184.216.34").isGlobalUnicast()).to.true;
        expect(Address4.parse("104.16.132.229").isGlobalUnicast()).to.true;
    });
    it("should not be global unicast", () => {
        expect(Address4.parse("0.0.0.0").isGlobalUnicast()).to.false;
        expect(Address4.parse("10.0.0.0").isGlobalUnicast()).to.false;
        expect(Address4.parse("127.0.0.1").isGlobalUnicast()).to.false;
        expect(Address4.parse("169.254.0.0").isGlobalUnicast()).to.false;
        expect(Address4.parse("172.16.0.0").isGlobalUnicast()).to.false;
        expect(Address4.parse("192.168.0.0").isGlobalUnicast()).to.false;
        expect(Address4.parse("224.0.0.0").isGlobalUnicast()).to.false;
        expect(Address4.parse("255.255.255.255").isGlobalUnicast()).to.false;
    });
});

describe("test isDocumentation()", () => {
    it("should be documentation", () => {
        expect(Address4.parse("192.0.2.0").isDocumentation()).to.true;
        expect(Address4.parse("198.51.100.0").isDocumentation()).to.true;
        expect(Address4.parse("203.0.113.0").isDocumentation()).to.true;
    });
    it("should not be documentation", () => {
        expect(Address4.parse("192.0.1.255").isDocumentation()).to.false;
        expect(Address4.parse("192.0.3.0").isDocumentation()).to.false;
        expect(Address4.parse("198.51.99.255").isDocumentation()).to.false;
        expect(Address4.parse("198.51.101.0").isDocumentation()).to.false;
        expect(Address4.parse("203.0.112.255").isDocumentation()).to.false;
        expect(Address4.parse("203.0.114.0").isDocumentation()).to.false;
    });
});

describe("test isShared()", () => {
    it("should be shared", () => {
        expect(Address4.parse("100.64.0.0").isShared()).to.true;
        expect(Address4.parse("100.127.255.255").isShared()).to.true;
    });
    it("should not be shared", () => {
        expect(Address4.parse("100.63.255.255").isShared()).to.false;
        expect(Address4.parse("100.128.0.0").isShared()).to.false;
    });
});

describe("test isGlobalReachable()", () => {
    it("should be global unicast", () => {
        expect(Address4.parse("93.184.216.34").isGlobalReachable()).to.true;
        expect(Address4.parse("104.16.132.229").isGlobalReachable()).to.true;
    });
    it("should not be global unicast", () => {
        expect(Address4.parse("0.0.0.0").isGlobalReachable()).to.false;
        expect(Address4.parse("10.0.0.0").isGlobalReachable()).to.false;
        expect(Address4.parse("100.127.255.255").isGlobalReachable()).to.false;
        expect(Address4.parse("100.64.0.0").isGlobalReachable()).to.false;
        expect(Address4.parse("127.0.0.1").isGlobalReachable()).to.false;
        expect(Address4.parse("169.254.0.0").isGlobalReachable()).to.false;
        expect(Address4.parse("172.16.0.0").isGlobalReachable()).to.false;
        expect(Address4.parse("192.0.2.0").isGlobalReachable()).to.false;
        expect(Address4.parse("192.168.0.0").isGlobalReachable()).to.false;
        expect(Address4.parse("198.51.100.0").isGlobalReachable()).to.false;
        expect(Address4.parse("203.0.113.0").isGlobalReachable()).to.false;
        expect(Address4.parse("224.0.0.0").isGlobalReachable()).to.false;
        expect(Address4.parse("255.255.255.255").isGlobalReachable()).to.false;
    });
});
