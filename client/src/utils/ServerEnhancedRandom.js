import axios from "axios";
import * as SecureStore from "expo-secure-store";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import enhancedRandom from "./EnhancedRandom";
import CONFIG from "../config/config";
import httpClient from "./httpClient";
import * as Crypto from "expo-crypto";

// Configuration from central config
const ENTROPY_SERVER_URL = CONFIG.ENTROPY_SERVER_URL;
const API_KEY = CONFIG.ENTROPY_API_KEY;
const ENTROPY_CACHE_KEY = "server_entropy_cache";
const CACHE_EXPIRY = CONFIG.ENTROPY_CACHE_EXPIRY;
const REQUEST_TIMEOUT = 2500; // REDUCED from 3000 to 2500ms for faster client experience
const HEALTH_CHECK_TIMEOUT = 1000; // REDUCED from 1500 to 1000ms for faster health checks
const MAX_PREFETCH_RETRIES = 3;
const MAX_CONSECUTIVE_FAILURES = 5; // After this many failures, we'll stop trying for a while
const FAILURE_BACKOFF_MAX = 60000; // Maximum backoff time (1 minute)
const INIT_TIMEOUT = 4000; // REDUCED from 5000 to 4000ms for faster initialization
const AUTO_PREFETCH_ENABLED = false; // Set to false to disable automatic background prefetching

// Configure axios for React Native to accept self-signed certificates
axios.defaults.timeout = REQUEST_TIMEOUT;
// In React Native, we use the global setting NODE_TLS_REJECT_UNAUTHORIZED in crypto-polyfill.js
// rather than the Node.js specific https agent

/**
 * Utility function to convert Uint8Array to hex string
 * (tweetnacl-util doesn't provide encodeHex directly)
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * ServerEnhancedRandom provides entropy that combines local device randomness
 * with server-side video-based entropy for maximum security
 */
class ServerEnhancedRandom {
  constructor() {
    this.serverAvailable = false; // Start assuming server is unavailable until verified
    this.lastServerCheck = 0;
    this.entropyCache = [];
    this.isInitialized = false;
    this.isPrefetching = false; // Flag to prevent multiple simultaneous prefetches
    this.prefetchFailures = 0; // Track consecutive prefetch failures
    this.backoffTime = 1000; // Initial backoff time in ms
    this.lastFailureTime = 0; // Last time a prefetch failed
    this.prefetchTimer = null; // Timer for scheduling next prefetch
    this.initializeAttempts = 0; // Track initialization attempts
    this.isInitializing = false; // Added for the new initialization logic
  }

  /**
   * Initialize by loading cached entropy and checking server availability
   */
  async initialize() {
    if (this.isInitialized) return true;

    // Store the start time to track how long this takes
    const startTime = Date.now();

    // Prevent concurrent initialization
    if (this.isInitializing) {
      // Wait for existing initialization to complete
      await new Promise((resolve) => {
        const checkInterval = setInterval(() => {
          if (this.isInitialized) {
            clearInterval(checkInterval);
            resolve();
          }
        }, 100);

        // Set a timeout to prevent waiting indefinitely
        setTimeout(() => {
          clearInterval(checkInterval);
          resolve();
        }, INIT_TIMEOUT);
      });

      console.log(
        `Waited for existing initialization, initialized: ${this.isInitialized}`
      );
      return this.isInitialized;
    }

    this.isInitializing = true;

    try {
      // Set a longer timeout for initialization to give it more time to complete
      const initPromise = new Promise(async (resolve) => {
        try {
          // The actual initialization process
          const initProcess = (async () => {
            // Try to load cached entropy - always do this first
            const cachedData = await SecureStore.getItemAsync(
              ENTROPY_CACHE_KEY
            );
            if (cachedData) {
              try {
                const parsed = JSON.parse(cachedData);
                if (parsed.expiry > Date.now()) {
                  this.entropyCache = parsed.seeds || [];
                  console.log(
                    `Loaded ${this.entropyCache.length} cached entropy seeds`
                  );
                } else {
                  console.log("Cached entropy expired");
                  await SecureStore.deleteItemAsync(ENTROPY_CACHE_KEY);
                  this.entropyCache = [];
                }
              } catch (cacheError) {
                console.log(
                  "Error parsing cached entropy, resetting:",
                  cacheError.message
                );
                await SecureStore.deleteItemAsync(ENTROPY_CACHE_KEY);
                this.entropyCache = [];
              }
            }

            // Initialize local enhanced randomness first - this must succeed
            await enhancedRandom.initialize();
            console.log("Local enhanced randomness initialized");

            // Now try to check if the entropy server is available
            try {
              // For initial connection, use an even shorter timeout
              const healthResponse = await httpClient.get(
                `${ENTROPY_SERVER_URL}/health`,
                { timeout: HEALTH_CHECK_TIMEOUT }
              );

              this.serverAvailable = healthResponse.status === 200;
              this.lastServerCheck = Date.now();

              if (this.serverAvailable) {
                console.log("Entropy server is available");

                // If the server is available and we have no cached seeds, prefetch some
                if (this.entropyCache.length === 0) {
                  try {
                    console.log("Prefetching initial entropy...");
                    // Get just one seed during initialization for improved startup speed
                    const response = await this.makeEntropyRequest(
                      "initialization",
                      32,
                      2 // Just 2 retries during init to keep it fast
                    );

                    if (response.data && response.data.seed) {
                      const seedData = {
                        seed: response.data.seed,
                        timestamp: Date.now(),
                      };
                      this.entropyCache.push(seedData);
                      await this.saveEntropyCache();
                      console.log("Initial entropy prefetch successful");
                    }
                  } catch (prefetchError) {
                    console.log(
                      "Initial entropy prefetch failed:",
                      prefetchError.message
                    );
                    // This is non-fatal - we'll continue with just local entropy
                  }
                }

                // Schedule background prefetch to fill up cache only if auto-prefetch is enabled
                if (this.entropyCache.length < 3 && AUTO_PREFETCH_ENABLED) {
                  this.schedulePrefetch(100); // Short delay to let app continue startup
                }
              } else {
                console.log("Entropy server is not available");
              }
            } catch (serverCheckError) {
              console.log(
                "Initial entropy server check failed:",
                serverCheckError.message
              );
              this.serverAvailable = false;
              this.lastServerCheck = Date.now();
            }

            return true;
          })();

          // Wait for the initialization process with a timeout
          const timeoutPromise = new Promise((r) =>
            setTimeout(() => r(false), INIT_TIMEOUT)
          );
          const initResult = await Promise.race([initProcess, timeoutPromise]);

          console.log(
            `Entropy initialization ${initResult ? "completed" : "timed out"}`
          );
          resolve(initResult);
        } catch (e) {
          console.error("Error in init promise:", e);
          resolve(false);
        }
      });

      // Wait for initialization to complete or timeout
      const initSucceeded = await initPromise;

      if (!initSucceeded) {
        console.log(
          "Entropy service initialization timed out, using partial initialization"
        );
      }

      // Even if parts of initialization failed, we'll consider the system initialized
      // as long as we have either local entropy (always) or cached server entropy
      this.isInitialized = true;
      this.isInitializing = false;

      const elapsed = Date.now() - startTime;
      console.log(
        `ServerEnhancedRandom initialization completed in ${elapsed}ms`
      );

      // Schedule a full prefetch in the background
      if (
        initSucceeded &&
        this.serverAvailable &&
        this.entropyCache.length < 3
      ) {
        setTimeout(() => this.prefetchEntropy(), 200);
      }

      return true;
    } catch (error) {
      console.error("Error initializing ServerEnhancedRandom:", error);
      // Fall back to local randomness only, but still use cached entropy if available
      this.serverAvailable = this.entropyCache.length > 0;
      if (this.serverAvailable) {
        console.log(
          `Using ${this.entropyCache.length} cached entropy seeds despite initialization error`
        );
      }
      this.isInitialized = true; // Still mark as initialized
      this.isInitializing = false;
      return false;
    }
  }

  /**
   * Schedule a prefetch with backoff timing
   */
  schedulePrefetch(delayMs = null) {
    // If auto-prefetch is disabled, don't schedule anything
    if (!AUTO_PREFETCH_ENABLED) {
      console.log("Auto-prefetch is disabled, not scheduling prefetch");
      return;
    }

    // Clear any existing timer
    if (this.prefetchTimer) {
      clearTimeout(this.prefetchTimer);
    }

    // Calculate delay if not provided
    if (delayMs === null) {
      // Use exponential backoff based on failures
      delayMs = Math.min(
        this.backoffTime * Math.pow(2, this.prefetchFailures - 1),
        FAILURE_BACKOFF_MAX
      );
    }

    console.log(`Scheduling next prefetch in ${delayMs}ms`);

    // Set the timer
    this.prefetchTimer = setTimeout(() => {
      // Don't await - we don't want to block anything
      this.prefetchEntropy().catch((err) => {
        console.log("Scheduled prefetch failed:", err.message);
      });
    }, delayMs);
  }

  /**
   * Check if the entropy server is available
   */
  async checkServerAvailability() {
    // Don't check too frequently - use cached value if checked recently
    const now = Date.now();
    if (now - this.lastServerCheck < 60000) {
      return this.serverAvailable;
    }

    try {
      // Use shorter timeout for health check with SSL validation disabled
      const response = await httpClient.get(`${ENTROPY_SERVER_URL}/health`, {
        timeout: HEALTH_CHECK_TIMEOUT,
        validateStatus: (status) => status === 200,
        // Bypass SSL certificate validation in React Native
        validateSSL: false,
      });

      const wasAvailable = this.serverAvailable;
      this.serverAvailable = response.status === 200;
      this.lastServerCheck = now;

      // If server just became available, log it and trigger prefetch
      if (!wasAvailable && this.serverAvailable) {
        console.log("Entropy server check result: available");
        console.log(
          `Updating server entropy availability from ${wasAvailable} to ${this.serverAvailable}`
        );
        // Reset backoff parameters when server becomes available
        this.prefetchFailures = 0;
        this.backoffTime = 1000;

        // If we have less than 3 seeds, trigger a prefetch
        if (this.entropyCache.length < 3 && !this.isPrefetching) {
          this.schedulePrefetch(0);
        }
      }

      return this.serverAvailable;
    } catch (error) {
      // Only log detailed error if this is a change in status
      if (this.serverAvailable) {
        console.warn("Entropy server unavailable:", error.message);
      }
      this.serverAvailable = false;
      this.lastServerCheck = now;
      return false;
    }
  }

  /**
   * Make a single entropy request with very aggressive timeouts and retry logic
   * to prevent hanging the app
   */
  async makeEntropyRequest(purpose = "prefetch", size = 32, retries = 1) {
    // Generate local entropy to send to server
    const localEntropyBytes = nacl.randomBytes(16);
    const localEntropy = bytesToHex(localEntropyBytes);

    let lastError = null;

    // Try multiple times with decreasing timeout
    for (let attempt = 0; attempt < retries; attempt++) {
      // Set up the request with aggressive timeout
      const timeout = Math.max(REQUEST_TIMEOUT - attempt * 500, 1500); // At least 1.5s timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await httpClient.post(
          `${ENTROPY_SERVER_URL}/api/get-seed`,
          {
            size: size,
            clientEntropy: localEntropy,
            purpose: purpose,
          },
          {
            headers: {
              "X-API-Key": API_KEY,
              "Content-Type": "application/json",
            },
            timeout: timeout,
            signal: controller.signal,
            // Bypass SSL certificate validation
            validateSSL: false,
          }
        );

        // Clear the timeout since request completed
        clearTimeout(timeoutId);

        if (response.data && response.data.seed) {
          // Success - return the response
          return response;
        }
      } catch (error) {
        // Clean up the timeout
        clearTimeout(timeoutId);

        lastError = error;
        console.log(
          `Entropy request attempt ${attempt + 1}/${retries} failed: ${
            error.message
          }`
        );

        // No need to retry server errors, only timeouts
        if (error.response) {
          break;
        }
      }
    }

    // All attempts failed
    throw lastError || new Error("Failed to fetch entropy after retries");
  }

  /**
   * Prefetch entropy from the server to avoid latency during cryptographic operations
   * @param {number} count - Number of seeds to prefetch
   * @param {number} maxPrefetchAttempts - Maximum attempts to make for the entire prefetch operation
   */
  async prefetchEntropy(count = 3, maxPrefetchAttempts = 1) {
    // Prevent multiple simultaneous prefetch operations
    if (this.isPrefetching) {
      console.log("Prefetch already in progress, skipping");
      return false;
    }

    // If we've had too many consecutive failures and not enough time has passed, skip
    const now = Date.now();
    if (
      this.prefetchFailures >= MAX_CONSECUTIVE_FAILURES &&
      now - this.lastFailureTime < this.backoffTime
    ) {
      console.log(
        `Skipping prefetch - too many recent failures (${this.prefetchFailures})`
      );
      return false;
    }

    // Check server availability, but don't retry if already checked recently
    if (!this.serverAvailable && now - this.lastServerCheck > 60000) {
      // Wrap in a timeout to prevent hanging
      try {
        const checkPromise = Promise.race([
          this.checkServerAvailability(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Server check timeout")), 3000)
          ),
        ]);

        this.serverAvailable = await checkPromise;
      } catch (error) {
        console.log("Server availability check failed:", error.message);
        this.serverAvailable = false;
      }
    }

    if (!this.serverAvailable) {
      console.log("Skipping prefetch - server unavailable");
      this.lastFailureTime = now;
      this.prefetchFailures++;

      // Only schedule another check if auto-prefetch is enabled
      if (AUTO_PREFETCH_ENABLED) {
        this.schedulePrefetch();
      }
      return false;
    }

    this.isPrefetching = true;

    try {
      // Track successful and fallback seeds
      let successCount = 0;
      let fallbackCount = 0;
      let attemptedCount = 0;

      // Make one request at a time to avoid overwhelming the server
      // This is more reliable than parallel requests which can cause timeouts
      const newEntropySources = [];

      // Limit prefetch attempts to just maxPrefetchAttempts (default 1)
      const prefetchAttempts = Math.min(count, maxPrefetchAttempts);

      for (let i = 0; i < prefetchAttempts; i++) {
        if (attemptedCount >= prefetchAttempts + 1) {
          // Don't keep trying if we've made too many attempts
          break;
        }

        attemptedCount++;

        try {
          // Make request with retry logic - strict timeout
          const response = await Promise.race([
            this.makeEntropyRequest("prefetch", 32, 2),
            new Promise(
              (_, reject) =>
                setTimeout(
                  () =>
                    reject(
                      new Error(`timeout of ${REQUEST_TIMEOUT}ms exceeded`)
                    ),
                  REQUEST_TIMEOUT + 1000
                ) // Add 1 second buffer
            ),
          ]);

          if (response && response.data && response.data.seed) {
            // Check the type of entropy provided
            if (response.data.fallback) {
              fallbackCount++;
              console.log("Server provided fallback entropy");
            } else {
              successCount++;
            }

            // Add to our new sources
            newEntropySources.push({
              seed: response.data.seed,
              source: response.data.source || "server",
              timestamp: now,
            });
          }
        } catch (error) {
          console.log(`Prefetch request ${i + 1} failed:`, error.message);
          continue; // Try next request
        }
      }

      // Update cache with new sources
      if (newEntropySources.length > 0) {
        // Add to the beginning of the cache (newest first)
        this.entropyCache = [...newEntropySources, ...this.entropyCache];

        // Cap the cache size
        if (this.entropyCache.length > 10) {
          this.entropyCache = this.entropyCache.slice(0, 10);
        }

        // Save the updated cache
        await this.saveEntropyCache();

        console.log(
          `Prefetch complete: Added ${newEntropySources.length} sources to cache (${successCount} full, ${fallbackCount} fallback)`
        );

        // Reset failure count on success
        this.prefetchFailures = 0;
        this.backoffTime = 1000;
        return true;
      } else {
        // All requests failed
        throw new Error("All prefetch requests failed");
      }
    } catch (error) {
      console.error(
        `Prefetch completely failed (attempt ${
          this.prefetchFailures + 1
        }), next retry in ${this.backoffTime / 1000}s`
      );

      // Track failure
      this.prefetchFailures++;
      this.lastFailureTime = now;

      // Increase backoff time for next attempt
      this.backoffTime = Math.min(this.backoffTime * 2, FAILURE_BACKOFF_MAX);

      // Only schedule another attempt if auto-prefetch is enabled
      if (AUTO_PREFETCH_ENABLED) {
        this.schedulePrefetch();
      }

      return false;
    } finally {
      this.isPrefetching = false;
    }
  }

  /**
   * Save the entropy cache to SecureStore
   */
  async saveEntropyCache() {
    try {
      const cacheData = {
        seeds: this.entropyCache,
        expiry: Date.now() + CACHE_EXPIRY,
      };
      await SecureStore.setItemAsync(
        ENTROPY_CACHE_KEY,
        JSON.stringify(cacheData)
      );
    } catch (error) {
      console.error("Error saving entropy cache:", error);
    }
  }

  /**
   * Get a seed from the entropy cache or fetch a new one
   * This is the main method used by cryptographic operations
   */
  async getServerSeed(size = 32) {
    if (!this.isInitialized) {
      await this.initialize();
    }

    // If we have cached entropy, use it
    if (this.entropyCache.length > 0) {
      const seedData = this.entropyCache.shift();

      // Schedule background prefetch if running low, but only if not already prefetching
      if (
        this.entropyCache.length < 2 &&
        !this.isPrefetching &&
        this.serverAvailable
      ) {
        // Use setTimeout to make this non-blocking
        setTimeout(() => {
          this.prefetchEntropy().catch((err) => {
            console.log("Background prefetch failed:", err.message);
          });
        }, 0);
      }

      // Save the updated cache after removing an item
      this.saveEntropyCache();

      return this.hexToBytes(seedData.seed);
    }

    // No cached entropy, try to fetch directly with a limited timeout
    if (await this.checkServerAvailability()) {
      try {
        console.log("Attempting to fetch entropy directly from server...");

        // Wrap the entropy request in a timeout to prevent hanging
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(
            () => reject(new Error("Direct entropy request timed out")),
            2500
          );
        });

        // Use the retry mechanism for direct requests too
        const requestPromise = this.makeEntropyRequest("immediate", size, 2);

        // Race the request against the timeout
        const response = await Promise.race([requestPromise, timeoutPromise]);

        if (response.data && response.data.seed) {
          // Check if this is a fallback response (server had an error but provided fallback entropy)
          if (response.data.fallback || response.data.prefetchDuringRefresh) {
            console.log("Server provided fallback entropy");
          } else {
            console.log("Successfully got entropy from server");
          }
          return this.hexToBytes(response.data.seed);
        }
      } catch (error) {
        console.log("Error fetching entropy directly:", error.message);
        // Mark the server as unavailable
        this.serverAvailable = false;
        this.lastServerCheck = Date.now();
      }
    }

    // Fall back to local randomness
    console.warn("Using local randomness only");
    return nacl.randomBytes(size);
  }

  /**
   * Convert hex string to bytes
   */
  hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  /**
   * Generate random bytes using combined local and server entropy
   * @param {number} size - Number of random bytes to generate
   */
  async getRandomBytes(size) {
    if (!this.isInitialized) {
      await this.initialize();
    }

    // Get entropy from both sources
    const localRandomness = await enhancedRandom.getRandomBytes(size);

    let serverRandomness;
    try {
      // Set a very tight timeout for server entropy to avoid blocking UI operations
      const timeoutPromise = new Promise((resolve) => {
        setTimeout(() => {
          resolve(nacl.randomBytes(size));
        }, 1000); // Use an even shorter timeout (1s) for random bytes generation
      });

      // Skip server entropy for very small values to reduce latency
      // Only try server entropy if we have cached seeds or server is known to be available
      if (
        size >= 16 && // Only use server for larger entropy needs (16+ bytes)
        (this.entropyCache.length > 0 || this.serverAvailable)
      ) {
        // Race the server seed request against the timeout
        serverRandomness = await Promise.race([
          this.getServerSeed(size),
          timeoutPromise,
        ]);
      } else {
        // For small entropy needs or when server is unavailable, use local source only
        serverRandomness = nacl.randomBytes(size);
      }
    } catch (error) {
      console.error("Error getting server entropy:", error);
      serverRandomness = nacl.randomBytes(size);
    }

    // Combine the entropy sources (XOR operation)
    const combined = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      combined[i] = localRandomness[i] ^ serverRandomness[i];
    }

    // Add one more layer of mixing if size is critical (32 bytes = key size)
    if (size === 32) {
      try {
        // Hash the combined entropy for critical values like keys
        // Convert Uint8Array to a format Expo Crypto can use
        const entropy = naclUtil.encodeBase64(combined);

        // Add timestamp to prevent predictability
        const timestamp = Date.now().toString();
        const hashInput = entropy + timestamp;

        // Use Expo's Crypto for hashing
        const hashHex = await Crypto.digestStringAsync(
          Crypto.CryptoDigestAlgorithm.SHA256,
          hashInput
        );

        // Convert hex string to Uint8Array
        const hashBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
          hashBytes[i] = parseInt(hashHex.substring(i * 2, i * 2 + 2), 16);
        }

        return hashBytes;
      } catch (error) {
        console.error("Error during final hashing:", error);
        // Fallback to just the combined entropy if hashing fails
        return combined;
      }
    }

    return combined;
  }

  /**
   * Generate a random box key pair with enhanced entropy
   * Direct replacement for nacl.box.keyPair()
   */
  async boxKeyPair() {
    // For critical key generation, use 32 bytes of server entropy
    const seed = await this.getRandomBytes(32);
    return nacl.box.keyPair.fromSecretKey(seed);
  }

  /**
   * Generate a random signing key pair with enhanced entropy
   * Direct replacement for nacl.sign.keyPair()
   */
  async signKeyPair() {
    // Set a maximum wait time for server entropy to avoid blocking registration
    const timeoutMs = 2000; // REDUCED from 3 seconds to 2 seconds maximum wait time

    // Create a promise that resolves with local entropy after timeout
    const timeoutPromise = new Promise((resolve) => {
      setTimeout(() => {
        console.log(
          "Server entropy taking too long for signing key, using local entropy"
        );
        resolve(enhancedRandom.getRandomBytes(32));
      }, timeoutMs);
    });

    // Create a promise for server entropy
    const serverEntropyPromise = this.getRandomBytes(32).catch((error) => {
      console.error("Error getting server entropy for signing key:", error);
      return enhancedRandom.getRandomBytes(32);
    });

    // Race the promises - use whichever completes first
    const seed = await Promise.race([serverEntropyPromise, timeoutPromise]);

    return nacl.sign.keyPair.fromSeed(seed);
  }

  /**
   * Generate identity keys with maximum entropy
   * For use in initial user registration
   */
  async generateIdentityKeyWithServerEntropy() {
    // Set a maximum wait time for server entropy to avoid blocking registration
    const timeoutMs = 2000; // REDUCED from 3 seconds to 2 seconds maximum wait time

    // Create a promise that resolves with local entropy after timeout
    const timeoutPromise = new Promise((resolve) => {
      setTimeout(() => {
        console.log(
          "Server entropy taking too long, falling back to local entropy"
        );
        resolve(enhancedRandom.getRandomBytes(32));
      }, timeoutMs);
    });

    // Create a promise for server entropy
    const serverEntropyPromise = this.getRandomBytes(32).catch((error) => {
      console.error("Error getting server entropy:", error);
      return enhancedRandom.getRandomBytes(32);
    });

    // Race the promises - use whichever completes first
    const seed = await Promise.race([serverEntropyPromise, timeoutPromise]);

    return nacl.box.keyPair.fromSecretKey(seed);
  }
}

// Export a singleton instance
const serverEnhancedRandom = new ServerEnhancedRandom();
export default serverEnhancedRandom;
