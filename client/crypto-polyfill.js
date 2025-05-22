import "react-native-get-random-values";
import { randomBytes } from "crypto";

// Polyfill za crypto.getRandomValues
if (!global.crypto) {
  global.crypto = {};
}

if (!global.crypto.getRandomValues) {
  global.crypto.getRandomValues = function (array) {
    const bytes = randomBytes(array.length);
    for (let i = 0; i < array.length; i++) {
      array[i] = bytes[i];
    }
    return array;
  };
}

// Configure environment for development
if (global.__DEV__) {
  console.log("Development mode: Configuring for self-signed certificates");

  // This is used by our httpClient for HTTPS connections
  global.SILENT_DISABLE_SSL_VALIDATION = true;

  // Patch XMLHttpRequest if needed
  global.XMLHttpRequest =
    global.originalXMLHttpRequest || global.XMLHttpRequest;
}

console.log("Crypto polyfill loaded");
