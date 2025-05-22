/**
 * Global configuration for Silent app
 * This centralizes configuration to make it easier to change values
 * without having to update multiple files.
 */

// Use environment variables if available, otherwise fallback to defaults
// Note: In React Native, we need to access these directly
const CONFIG = {
  // API endpoints
  BACKEND_URL: process.env.REACT_APP_BACKEND_URL || "https://192.168.1.85:3000",
  ENTROPY_SERVER_URL:
    process.env.REACT_APP_ENTROPY_SERVER_URL || "http://192.168.1.85:5000",

  // API keys
  ENTROPY_API_KEY:
    process.env.REACT_APP_ENTROPY_API_KEY || "development-only-key",

  // Timeouts (in milliseconds)
  ENTROPY_REQUEST_TIMEOUT: 30000, // 30 seconds
  API_REQUEST_TIMEOUT: 30000, // 30 seconds

  // Cache durations (in milliseconds)
  ENTROPY_CACHE_EXPIRY: 3600000, // 1 hour

  // SSL validation settings
  VALIDATE_SSL: false, // Disable SSL validation in development

  // Development flags
  IS_DEVELOPMENT: true, // Set to false in production builds
};

export default CONFIG;
