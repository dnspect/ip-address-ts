import { AddressError } from "./error";
import { Address4 } from "./ipv4";
import { Address6 } from "./ipv6";
import { expect, use } from "chai";
import chaibytes from "chai-bytes";

use(chaibytes);

describe("test parse()", () => {
    it("should throw error", () => {
        expect(() => Address6.parse("")).to.throw(AddressError, "malformed IPv6 address: ");
        expect(() => Address6.parse(":")).to.throw(AddressError, "malformed IPv6 address: :");
        expect(() => Address6.parse(" ::")).to.throw(AddressError, `malformed IPv6 address: " " is unexpected`);
        expect(() => Address6.parse("::%abc")).to.throw(AddressError, "malformed IPv6 address: unspecified address (::) should not have a scope");
        expect(() => Address6.parse(":::")).to.throw(AddressError, `malformed IPv6 address: ":::" is unexpected`);
        expect(() => Address6.parse("2001:db8:::1")).to.throw(AddressError, `malformed IPv6 address: ":::" is unexpected`);
        expect(() => Address6.parse("2001:db8::1:foo")).to.throw(AddressError, `malformed IPv6 address: "oo" is unexpected`);
        expect(() => Address6.parse("2001:db8::1::")).to.throw(AddressError, `malformed IPv6 address: too many "::" groups found`);
        expect(() => Address6.parse("2001:db8::0")).to.throw(AddressError, `malformed IPv6 address: "::0" is unexpected`);
        expect(() => Address6.parse("2001:db8::0:1:0:0:1")).to.throw(AddressError, `malformed IPv6 address: "::0:" is unexpected`);
        expect(() => Address6.parse("1:2::4:5:6:7:8")).to.throw(AddressError, `malformed IPv6 address: "::" should represent at least two consecutive all-zero fields`);
        expect(() => Address6.parse("2001:db8::1.2.3")).to.throw(AddressError, `malformed IPv6 address: "." is unexpected`);
    });

    it("should parse", () => {
        expect(Address6.parse("::").toString()).to.equal("::");
        expect(Address6.parse("::1").toString()).to.equal("::1");
        expect(Address6.parse("1::").toString()).to.equal("1::");
        expect(Address6.parse("2001:db8::1").toString()).to.equal("2001:db8::1");
        expect(Address6.parse("2001:db8::203.0.113.1").toString()).to.equal("2001:db8::cb00:7101");
    });

    it("should parse with zone", () => {
        expect(Address6.parse("::1%").zone()).to.equal("");
        expect(Address6.parse("::1%0").zone()).to.equal("0");
        expect(Address6.parse("::1%abc").zone()).to.equal("abc");
        expect(Address6.parse("1::%abc").zone()).to.equal("abc");
        expect(Address6.parse("1::%abc%:.k").zone()).to.equal("abc%:.k");
        expect(Address6.parse("2001:db8::1%abc").zone()).to.equal("abc");
        expect(Address6.parse("2001:db8::203.0.113.1%abc").zone()).to.equal("abc");
    });
});

describe("test toString()", () => {
    it("should return canonical text", () => {
        expect(Address6.parse("2001:db8:0:0:1:0:0:1").toString()).to.equal("2001:db8::1:0:0:1");
        expect(Address6.parse("2001:db8::1:0:0:1").toString()).to.equal("2001:db8::1:0:0:1");
        expect(Address6.parse("2001:db8:0:0:1::1").toString()).to.equal("2001:db8::1:0:0:1");
        expect(Address6.parse("2001:db8:0000:0:1::1").toString()).to.equal("2001:db8::1:0:0:1");
        expect(Address6.parse("2001:DB8:0:0:1::1").toString()).to.equal("2001:db8::1:0:0:1");
    });
});

describe("test fromAddress4()", () => {
    it("should throw error", () => {
        expect(() => Address6.fromAddress4("")).to.throw(AddressError, "invalid IPv4 address");
        expect(() => Address6.fromAddress4("1.2.3")).to.throw(AddressError, "invalid IPv4 address");
    });

    it("should return address", () => {
        expect(Address6.fromAddress4("0.0.0.0").toString()).to.equal("::ffff:0:0");
        expect(Address6.fromAddress4("0.0.0.1").toString()).to.equal("::ffff:0:1");
        expect(Address6.fromAddress4("255.255.255.255").toString()).to.equal("::ffff:ffff:ffff");
    });
});

describe("test fromArpa()", () => {
    it("should throw error", () => {
        expect(() => Address6.fromArpa("")).to.throw(AddressError, "invalid ip6.arpa. address");
        expect(() => Address6.fromArpa("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa")).to.throw(AddressError, "invalid ip6.arpa. address");
    });

    it("should return address", () => {
        expect(Address6.fromArpa("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.").toString()).to.equal("::");
        expect(Address6.fromArpa("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.ip6.arpa.").toString()).to.equal("1000::");
        expect(Address6.fromArpa("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa.").toString()).to.equal("1::");
        expect(Address6.fromArpa("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.").toString()).to.equal("::1");
        expect(Address6.fromArpa("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.").toString()).to.equal("::1");
    });
});

describe("test toArpa()", () => {
    it("should return ip6.arpa. address", () => {
        expect(Address6.parse("::").toArpa()).to.equal("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.");
        expect(Address6.parse("::1").toArpa()).to.equal("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.");
        expect(Address6.parse("1::").toArpa()).to.equal("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa.");
        expect(Address6.parse("1000::").toArpa()).to.equal("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.ip6.arpa.");
        expect(Address6.parse("::1").toArpa({ omitSuffix: true })).to.equal("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0");
    });
});

describe("test fromBytes()", () => {
    it("should throw error", () => {
        expect(() => Address6.fromBytes(new Uint8Array(0))).to.throw(AddressError, "invalid number of bytes");
        expect(() => Address6.fromBytes(new Uint8Array(15))).to.throw(AddressError, "invalid number of bytes");
    });

    it("should return address", () => {
        expect(Address6.fromBytes(new Uint8Array(16)).toString()).to.equal("::");
        expect(Address6.fromBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1])).toString()).to.equal("::1");
        expect(Address6.fromBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10])).toString()).to.equal("::10");
        expect(Address6.fromBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0])).toString()).to.equal("::100");
        expect(Address6.fromBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0])).toString()).to.equal("::1000");
        expect(Address6.fromBytes(new Uint8Array([0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])).toString()).to.equal("1::");
        expect(Address6.fromBytes(new Uint8Array([0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])).toString()).to.equal("10::");
        expect(Address6.fromBytes(new Uint8Array([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])).toString()).to.equal("100::");
        expect(Address6.fromBytes(new Uint8Array([0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])).toString()).to.equal("1000::");
        expect(Address6.fromBytes(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])).toString()).to.equal("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    });
});

describe("test bytes()", () => {
    it("should return bytes", () => {
        expect(Address6.parse("::").bytes()).to.equalBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]));
        expect(Address6.parse("::1").bytes()).to.equalBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1]));
        expect(Address6.parse("::10").bytes()).to.equalBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10]));
        expect(Address6.parse("::100").bytes()).to.equalBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0]));
        expect(Address6.parse("::1000").bytes()).to.equalBytes(new Uint8Array([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0]));
        expect(Address6.parse("1::").bytes()).to.equalBytes(new Uint8Array([0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]));
        expect(Address6.parse("10::").bytes()).to.equalBytes(new Uint8Array([0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]));
        expect(Address6.parse("100::").bytes()).to.equalBytes(new Uint8Array([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]));
        expect(Address6.parse("1000::").bytes()).to.equalBytes(new Uint8Array([0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]));
        expect(Address6.parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").bytes()).to.equalBytes(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
    });
});

describe("test toHex()", () => {
    it("should return hex string", () => {
        expect(Address6.parse("::").toHex()).to.equal("0000:0000:0000:0000:0000:0000:0000:0000");
        expect(Address6.parse("::1").toHex()).to.equal("0000:0000:0000:0000:0000:0000:0000:0001");
        expect(Address6.parse("::10").toHex()).to.equal("0000:0000:0000:0000:0000:0000:0000:0010");
        expect(Address6.parse("1::").toHex()).to.equal("0001:0000:0000:0000:0000:0000:0000:0000");
        expect(Address6.parse("10::").toHex()).to.equal("0010:0000:0000:0000:0000:0000:0000:0000");
    });
});

describe("test toBinaryString()", () => {
    it("should return zero-padded base-2 string", () => {
        expect(Address6.parse("::").toBinaryString()).to.equal("0".repeat(128));
        expect(Address6.parse("::1").toBinaryString()).to.equal("0".repeat(127) + 1);
        expect(Address6.parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").toBinaryString()).to.equal("1".repeat(128));
    });
});

describe("test isIPv4()", () => {
    it("should never be IPv4 event it can be converted to an IPv4 address", () => {
        expect(Address6.parse("::").isIPv4()).to.false;
        expect(Address6.parse("::1").isIPv4()).to.false;
        expect(Address6.parse("::ffff:cb00:7001").isIPv4()).to.false;
        expect(Address6.parse("2001:db8::203.0.112.1").isIPv4()).to.false;
    });
});

describe("test toIPv4()", () => {
    it("should return null", () => {
        expect(Address6.parse("1::").toIPv4()).to.null;
        expect(Address6.parse("::ffff:2:0:0").toIPv4()).to.null;
    });
    it("should return Address4", () => {
        expect(Address6.parse("::1").toIPv4()?.toString(), "loopback").to.equal("127.0.0.1");
        expect(Address6.parse("::").toIPv4()?.toString(), " IPv4 compatible (unspecified)").to.equal("0.0.0.0");
        expect(Address6.parse("::cb00:7001").toIPv4()?.toString(), "IPv4 compatible").to.equal("203.0.112.1");
        expect(Address6.parse("::ffff:ffff").toIPv4()?.toString(), "IPv4 compatible").to.equal("255.255.255.255");
        expect(Address6.parse("::ffff:cb00:7001").toIPv4()?.toString(), "IPv4-mapped").to.equal("203.0.112.1");
        expect(Address6.parse("::ffff:0:cb00:7001").toIPv4()?.toString(), "IPv4 translated").to.equal("203.0.112.1");
        expect(Address6.parse("2001:db8::203.0.112.1").toIPv4()?.toString(), "4in6").to.equal("203.0.112.1");
    });
});

describe("test to4in6()", () => {
    it("should return v4-in-v6 form representation", () => {
        expect(Address6.parse("::").to4in6()).to.equal("::0.0.0.0");
        expect(Address6.parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").to4in6()).to.equal("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255");
    });
});

describe("test isCanonical()", () => {
    it("should not be canonical", () => {
        expect(Address6.parse("01::").isCanonical()).to.false;
        expect(Address6.parse("1::%").isCanonical()).to.false;
        expect(Address6.parse("0:0:0:0:0:0:0:0").isCanonical()).to.false;
    });

    it("should be canonical", () => {
        expect(Address6.parse("::").isCanonical()).to.true;
        expect(Address6.parse("1::").isCanonical()).to.true;
        expect(Address6.parse("1::%0").isCanonical()).to.true;
        expect(Address6.parse("1::%abcd.%k:").isCanonical()).to.true;
        expect(Address6.parse("1000::").isCanonical()).to.true;
    });
});


describe("test mappedTo6()", () => {
    it("should return IPv4-mapped IPv6 address", () => {
        expect(Address6.mappedFrom(Address4.parse("0.0.0.0")).toString()).to.equal("::ffff:0:0");
        expect(Address6.mappedFrom(Address4.parse("255.255.255.255")).toString()).to.equal("::ffff:ffff:ffff");
    });
});

describe("test translatedFrom()", () => {
    it("should return IPv4 translated IPv6 address", () => {
        expect(Address6.translatedFrom(Address4.parse("0.0.0.0")).toString()).to.equal("::ffff:0:0:0");
        expect(Address6.translatedFrom(Address4.parse("255.255.255.255")).toString()).to.equal("::ffff:0:ffff:ffff");
    });
});

describe("test isUnspecified()", () => {
    it("should be unspecified", () => {
        expect(Address6.parse("::").isUnspecified()).to.true;
    });

    it("should not be unspecified", () => {
        expect(Address6.parse("::1").isUnspecified()).to.false;
    });
});
