import { Buffer } from "buffer";

// Polyfill za utf-16le
const originalFrom = Buffer.from;
Buffer.from = function (data, encoding) {
  if (encoding === "utf-16le" || encoding === "utf16le") {
    console.warn("utf-16le detected, converting to utf-8");
    if (typeof data === "string") {
      // Konvertuj string u Uint8Array koristeći TextEncoder
      const encoder = new TextEncoder();
      return originalFrom(encoder.encode(data));
    } else if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
      return originalFrom(data);
    } else {
      throw new Error("Unsupported data type for utf-16le");
    }
  }
  return originalFrom(data, encoding);
};

// Proveri da li Buffer radi
console.log("Buffer polyfill loaded:", Buffer.from("test").toString("base64"));

export { Buffer };
