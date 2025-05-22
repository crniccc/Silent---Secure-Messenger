import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import "react-native-get-random-values";
import * as FileSystem from "expo-file-system";
import * as Crypto from "expo-crypto";
import * as SecureStore from "expo-secure-store";

/**
 * EnhancedRandom provides improved randomness by combining multiple entropy sources
 * It should be used for critical cryptographic operations like key generation
 */
class EnhancedRandom {
  constructor() {
    this.entropyPool = new Uint8Array(0);
    this.lastRefresh = 0;
    this.refreshInterval = 24 * 60 * 60 * 1000; // 24 hours in ms
    this.initialized = false;
    this.initPromise = null;
  }

  /**
   * Initialize the entropy pool
   * This should be called early in app startup
   */
  async initialize() {
    if (this.initialized) return;

    // Use a promise to prevent multiple simultaneous initializations
    if (this.initPromise) return this.initPromise;

    this.initPromise = this._refreshEntropyPool();
    await this.initPromise;

    this.initialized = true;
    this.initPromise = null;
  }

  /**
   * Generate random bytes using enhanced entropy
   * @param {number} size - Number of random bytes to generate
   * @returns {Uint8Array} - Random bytes
   */
  async getRandomBytes(size) {
    // Ensure we're initialized
    if (!this.initialized) {
      await this.initialize();
    }

    // Check if we need to refresh our entropy pool
    const now = Date.now();
    if (
      now - this.lastRefresh > this.refreshInterval ||
      this.entropyPool.length < size * 2
    ) {
      await this._refreshEntropyPool();
    }

    // Start with TweetNaCl randomness
    const naclRandom = nacl.randomBytes(size);

    // Extract entropy from our pool
    const entropySlice = this.entropyPool.slice(0, size);

    // Remove used entropy and schedule refresh if needed
    this.entropyPool = this.entropyPool.slice(size);
    if (this.entropyPool.length < size * 4) {
      // Don't await - let it refresh in background
      this._refreshEntropyPool();
    }

    // Combine the sources (XOR operation)
    const combined = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      combined[i] = naclRandom[i] ^ entropySlice[i % entropySlice.length];
    }

    // Hash the result for uniform distribution
    if (size <= 32) {
      const hash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        naclUtil.encodeBase64(combined)
      );
      return naclUtil.decodeBase64(hash).slice(0, size);
    } else {
      // For larger sizes, use multiple hashes
      const result = new Uint8Array(size);
      let offset = 0;

      while (offset < size) {
        const hashInput = naclUtil.encodeBase64(combined) + offset.toString();
        const hash = await Crypto.digestStringAsync(
          Crypto.CryptoDigestAlgorithm.SHA256,
          hashInput
        );
        const hashBytes = naclUtil.decodeBase64(hash);

        const copySize = Math.min(32, size - offset);
        for (let i = 0; i < copySize; i++) {
          result[offset + i] = hashBytes[i];
        }

        offset += 32;
      }

      return result;
    }
  }

  /**
   * Refresh the entropy pool with new random data from multiple sources
   * @private
   */
  async _refreshEntropyPool() {
    console.log("Refreshing entropy pool...");

    try {
      // Gather entropy from various device sources
      const entropyChunks = [];

      // 1. Start with native TweetNaCl entropy
      entropyChunks.push(nacl.randomBytes(256));

      // 2. Add expo-crypto randomness
      const expoCryptoRandom = await Crypto.getRandomBytesAsync(256);
      entropyChunks.push(new Uint8Array(expoCryptoRandom));

      // 3. Device-specific entropy
      try {
        // Cache dir info as entropy source
        const cacheInfo = await FileSystem.getInfoAsync(
          FileSystem.cacheDirectory
        );
        const cacheInfoStr = JSON.stringify(cacheInfo);
        const cacheHash = await Crypto.digestStringAsync(
          Crypto.CryptoDigestAlgorithm.SHA256,
          cacheInfoStr
        );
        entropyChunks.push(naclUtil.decodeBase64(cacheHash));
      } catch (error) {
        console.log("Error getting cache info for entropy:", error);
      }

      // 4. Use stored history of previous entropy
      try {
        const storedEntropy = await SecureStore.getItemAsync(
          "enhancedRandomEntropy"
        );
        if (storedEntropy) {
          entropyChunks.push(naclUtil.decodeBase64(storedEntropy));
        }
      } catch (error) {
        console.log("Error retrieving stored entropy:", error);
      }

      // 5. Timing-based entropy (microsecond variations)
      const timingEntropy = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        const start = Date.now();
        for (let j = 0; j < 1000; j++) {
          // Empty loop to capture CPU timing variations
        }
        const end = Date.now();
        timingEntropy[i] = (end - start) & 0xff;
      }
      entropyChunks.push(timingEntropy);

      // Combine all entropy chunks
      let totalLength = 0;
      entropyChunks.forEach((chunk) => {
        totalLength += chunk.length;
      });

      const combinedEntropy = new Uint8Array(totalLength);
      let offset = 0;

      entropyChunks.forEach((chunk) => {
        combinedEntropy.set(chunk, offset);
        offset += chunk.length;
      });

      // Hash the combined entropy for better distribution
      const entropyHash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA512,
        naclUtil.encodeBase64(combinedEntropy)
      );

      // Store some entropy for future use
      await SecureStore.setItemAsync(
        "enhancedRandomEntropy",
        entropyHash.substring(0, 64) // Store first 64 chars of hash
      );

      // Set as our new entropy pool
      this.entropyPool = naclUtil.decodeBase64(entropyHash);
      this.lastRefresh = Date.now();

      console.log(
        `Entropy pool refreshed: ${this.entropyPool.length} bytes collected`
      );
    } catch (error) {
      console.error("Error refreshing entropy pool:", error);
      // Fallback to nacl randomness if our enhancement fails
      this.entropyPool = nacl.randomBytes(512);
    }
  }

  /**
   * Generate a random key pair with enhanced entropy
   * Direct replacement for nacl.box.keyPair()
   */
  async boxKeyPair() {
    // Generate random seed
    const seed = await this.getRandomBytes(32);
    return nacl.box.keyPair.fromSecretKey(seed);
  }

  /**
   * Generate a random signing key pair with enhanced entropy
   * Direct replacement for nacl.sign.keyPair()
   */
  async signKeyPair() {
    // Generate random seed
    const seed = await this.getRandomBytes(32);
    return nacl.sign.keyPair.fromSeed(seed);
  }
}

// Export a singleton instance
const enhancedRandom = new EnhancedRandom();
export default enhancedRandom;
