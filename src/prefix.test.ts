import { AddressError } from "./error";
import { Address4 } from "./ipv4";
import { Address6 } from "./ipv6";
import { Prefix } from "./prefix";
import { expect } from "chai";

describe("test parse()", () => {
    it("should throw error", () => {
        expect(() => Prefix.parse("")).to.throw(AddressError, `malformed prefix: "/" not found`);
        expect(() => Prefix.parse("/24")).to.throw(AddressError, `malformed prefix: "/" not found`);
        expect(() => Prefix.parse("0/24")).to.throw(AddressError, `invalid IPv4 address: 0`);
        expect(() => Prefix.parse(":/24")).to.throw(AddressError, `malformed IPv6 address: :`);
        expect(() => Prefix.parse("203.0.113.0/48")).to.throw(AddressError, `prefix length out of range: 48`);
        expect(() => Prefix.parse("::/129")).to.throw(AddressError, `prefix length out of range: 129`);
    });

    it("should return prefix", () => {
        expect(Prefix.parse("0.0.0.0/0").toString()).to.equal(new Prefix(Address4.parse("0.0.0.0"), 0).toString());
        expect(Prefix.parse("203.0.113.0/24").toString()).to.equal(new Prefix(Address4.parse("203.0.113.0"), 24).toString());
        expect(Prefix.parse("::/0").toString()).to.equal(new Prefix(Address6.parse("::"), 0).toString());
        expect(Prefix.parse("2001:db8::/32").toString()).to.equal(new Prefix(Address6.parse("2001:db8::"), 32).toString());
    });
});

describe("test isSingleIP()", () => {
    it("should return false", () => {
        expect(Prefix.parse("203.0.113.0/24").isSingleIP()).to.false;
        expect(Prefix.parse("2001:db8::/32").isSingleIP()).to.false;
    });

    it("should return true", () => {
        expect(Prefix.parse("203.0.113.0/32").isSingleIP()).to.true;
        expect(Prefix.parse("2001:db8::/128").isSingleIP()).to.true;
    });
});

describe("test firstIP()", () => {
    it("should return first IPv4 address in the range", () => {
        expect(Prefix.parse("203.0.113.1/16").firstIP().toString()).to.equal("203.0.0.0");
        expect(Prefix.parse("203.0.113.1/17").firstIP().toString()).to.equal("203.0.0.0");
        expect(Prefix.parse("203.0.113.1/18").firstIP().toString()).to.equal("203.0.64.0");
        expect(Prefix.parse("203.0.113.1/19").firstIP().toString()).to.equal("203.0.96.0");
        expect(Prefix.parse("203.0.113.1/20").firstIP().toString()).to.equal("203.0.112.0");
        expect(Prefix.parse("203.0.113.1/24").firstIP().toString()).to.equal("203.0.113.0");
        expect(Prefix.parse("203.0.113.1/32").firstIP().toString()).to.equal("203.0.113.1");
    });

    it("should return first IPv6 address in the range", () => {
        expect(Prefix.parse("2001:db8::1/28").firstIP().toString()).to.equal("2001:db0::");
        expect(Prefix.parse("2001:db8::1/32").firstIP().toString()).to.equal("2001:db8::");
    });
});

describe("test toMasked()", () => {
    it("should return canonical form IPv4 address prefix", () => {
        expect(Prefix.parse("203.0.113.1/16").toMasked().toString()).to.equal("203.0.0.0/16");
        expect(Prefix.parse("203.0.113.1/17").toMasked().toString()).to.equal("203.0.0.0/17");
        expect(Prefix.parse("203.0.113.1/18").toMasked().toString()).to.equal("203.0.64.0/18");
        expect(Prefix.parse("203.0.113.1/19").toMasked().toString()).to.equal("203.0.96.0/19");
        expect(Prefix.parse("203.0.113.1/20").toMasked().toString()).to.equal("203.0.112.0/20");
        expect(Prefix.parse("203.0.113.1/24").toMasked().toString()).to.equal("203.0.113.0/24");
        expect(Prefix.parse("203.0.113.1/32").toMasked().toString()).to.equal("203.0.113.1/32");
    });

    it("should return canonical form IPv6 address prefix", () => {
        expect(Prefix.parse("2001:db8::1/28").toMasked().toString()).to.equal("2001:db0::/28");
        expect(Prefix.parse("2001:db8::1/32").toMasked().toString()).to.equal("2001:db8::/32");
    });
});

describe("test contains()", () => {
    it("should contain (IPv4)", () => {
        expect(Prefix.parse("0.0.0.0/8").contains(Address6.parse("::")), "IPv6 address will not match an IPv4 prefix").to.false;
        expect(Prefix.parse("203.0.113.0/24").contains(Address4.parse("203.0.112.255"))).to.false;
        expect(Prefix.parse("203.0.113.0/24").contains(Address4.parse("203.0.113.0"))).to.true;
        expect(Prefix.parse("203.0.113.0/24").contains(Address4.parse("203.0.113.255"))).to.true;
        expect(Prefix.parse("203.0.113.0/24").contains(Address4.parse("203.0.114.0"))).to.false;
        expect(Prefix.parse("203.0.113.1/32").contains(Address4.parse("203.0.113.0"))).to.false;
        expect(Prefix.parse("203.0.113.1/32").contains(Address4.parse("203.0.113.1"))).to.true;
        expect(Prefix.parse("203.0.113.1/32").contains(Address4.parse("203.0.113.2"))).to.false;
        expect(Prefix.parse("203.0.113.1/32").contains(Address6.mappedFrom(Address4.parse("203.0.113.1"))), "v4-mapped address should not match the IPv4 prefix").to.false;
        expect(Prefix.parse("203.0.113.1/32").contains(Address6.translatedFrom(Address4.parse("203.0.113.1"))), "v4 translated address should not match the IPv4 prefix").to.false;
    });

    it("should contain (IPv6)", () => {
        expect(Prefix.parse("::/8").contains(Address4.parse("0.0.0.0")), "IPv4 address will not match an IPv6 prefix").to.false;
        expect(Prefix.parse("2001:db8::/32").contains(Address6.parse("2001:0db7:ffff:ffff:ffff:ffff:ffff:ffff"))).to.false;
        expect(Prefix.parse("2001:db8::/32").contains(Address6.parse("2001:db8::"))).to.true;
        expect(Prefix.parse("2001:db8::/32").contains(Address6.parse("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"))).to.true;
        expect(Prefix.parse("2001:db8::/32").contains(Address6.parse("2001:db9::"))).to.false;
        expect(Prefix.parse("2001:db8::1/128").contains(Address6.parse("2001:db8::"))).to.false;
        expect(Prefix.parse("2001:db8::1/128").contains(Address6.parse("2001:db8::1"))).to.true;
        expect(Prefix.parse("2001:db8::1/128").contains(Address6.parse("2001:db8::2"))).to.false;
        expect(Prefix.parse("::ffff:203.0.113.1/128").contains(Address4.parse("203.0.113.1")), "IPv4 address should not match the v4-mapped prefix").to.false;
        expect(Prefix.parse("::ffff:0:203.0.113.1/128").contains(Address4.parse("203.0.113.1")), "IPv4 address should not match the v4 translated prefix").to.false;
    });
});
