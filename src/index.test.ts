import { expect } from "chai";
import { AddressError, validate, parse } from ".";

describe("test validate()", () => {
    it("should be valid", () => {
        expect(validate('0.0.0.0')).to.be.true;
        expect(validate('::')).to.be.true;
        expect(validate('::1')).to.be.true;
        expect(validate('::1%abc')).to.be.true;
        expect(validate('::1%abc%:.k')).to.be.true;
    });
    it("should be invalid", () => {
        expect(validate('0.0.0')).to.be.false;
        expect(validate(':::')).to.be.false;
        expect(validate('1::1::1')).to.be.false;
        expect(validate('::%abc')).to.be.false;
    });
});

describe("test parse()", () => {
    it("should parse", () => {
        expect(parse('0.0.0.0').isIPv4()).to.be.true;
        expect(parse('::').isIPv6()).to.be.true;
        expect(parse('::1').isIPv6()).to.be.true;
        expect(parse('::1%abc').isIPv6()).to.be.true;
        expect(parse('::1%abc%:.k').isIPv6()).to.be.true;
    });
    it("should throw error", () => {
        expect(() => parse('0.0.0')).to.throw(AddressError);
        expect(() => parse(':::')).to.throw(AddressError);
        expect(() => parse('1::1::1')).to.throw(AddressError);
        expect(() => parse('::%abc')).to.throw(AddressError);
    });
});
