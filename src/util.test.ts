import { compareNumberArray, hex, uint8ArrayToUint16Array, uint16ArrayToUint8Array } from "./util";
import { expect } from "chai";

describe("test hex()", () => {
    it("should generate hex string correctly", () => {
        expect(hex(0)).to.equal("0");
        expect(hex(0, 2)).to.equal("00");
        expect(hex(0, 2, true)).to.equal("0x00");
        expect(hex(15)).to.equal("f");
        expect(hex(15, 2)).to.equal("0f");
        expect(hex(15, 2, true)).to.equal("0x0f");
        expect(hex(16)).to.equal("10");
        expect(hex(16, 2)).to.equal("10");
        expect(hex(16, 2, true)).to.equal("0x10");
        expect(hex(255)).to.equal("ff");
        expect(hex(255, 2)).to.equal("ff");
        expect(hex(255, 2, true)).to.equal("0xff");
        expect(hex(256)).to.equal("100");
        expect(hex(256, 4)).to.equal("0100");
        expect(hex(256, 4, true)).to.equal("0x0100");
    });
});

describe("test compareNumberArray()", () => {
    it("should not equal", () => {
        expect(compareNumberArray(new Uint8Array(0), new Uint8Array(1))).to.false;
        expect(compareNumberArray(new Uint8Array([1, 1]), new Uint8Array([2]))).to.false;
        expect(compareNumberArray(new Uint8Array([1, 2]), new Uint8Array([2, 1]))).to.false;
        expect(compareNumberArray(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]), 2)).to.false;
        expect(compareNumberArray(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]), 0, 3)).to.false;
    });

    it("should equal", () => {
        expect(compareNumberArray(new Uint8Array(0), new Uint8Array(0))).to.true;
        expect(compareNumberArray(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).to.true;
        expect(compareNumberArray(new Uint8Array([2, 1]), new Uint16Array([2, 1]))).to.true;
        expect(compareNumberArray(new Uint16Array([2, 1]), new Uint16Array([2, 1]))).to.true;
        expect(compareNumberArray(new Uint16Array([1, 2, 4, 3]), new Uint16Array([1, 2, 3, 4]), 0, 2)).to.true;
        expect(compareNumberArray(new Uint16Array([4, 2, 3, 1]), new Uint16Array([1, 2, 3, 4]), 1, 3)).to.true;
    });
});

describe("test uint8ArrayToUint16Array()", () => {
    it("should throw error", () => {
        expect(() => uint8ArrayToUint16Array(new Uint8Array(1))).to.throw(Error, "length of the Uint8Array should be even");
        expect(() => uint8ArrayToUint16Array(new Uint8Array(3))).to.throw(Error, "length of the Uint8Array should be even");
    });

    it("should return Uint16Array", () => {
        expect(compareNumberArray(uint8ArrayToUint16Array(new Uint8Array(2)), new Uint16Array(1))).to.true;
        expect(compareNumberArray(uint8ArrayToUint16Array(new Uint8Array([0x0, 0x0, 0xFF, 0xFF])), new Uint16Array([0x0, 0xFFFF]))).to.true;
    });
});


describe("test uint16ArrayToUint8Array()", () => {
    it("should return Uint8Array", () => {
        expect(uint16ArrayToUint8Array(new Uint16Array(1))).to.equalBytes(new Uint8Array(2));
        expect(uint16ArrayToUint8Array(new Uint16Array([0x0, 0xFFFF]))).to.equalBytes(new Uint8Array([0x0, 0x0, 0xFF, 0xFF]));
    });
});
