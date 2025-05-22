import axios from "axios";
import CONFIG from "../config/config";

// Create custom axios instance that configures connections appropriately
const httpClient = axios.create({
  headers: {
    "Content-Type": "application/json",
  },
});

// Configure the client with proper timeout
httpClient.defaults.timeout = CONFIG.API_REQUEST_TIMEOUT || 30000;

// Add request interceptor to handle SSL validation in React Native
httpClient.interceptors.request.use((config) => {
  // Only apply SSL validation bypass for HTTPS connections
  if (config.url && config.url.startsWith("https://")) {
    // Add required config for SSL bypass
    config.validateSSL = false;
    console.log(`HTTPS request with SSL validation disabled: ${config.url}`);
  } else {
    console.log(`HTTP request: ${config.url}`);
  }

  // For React Native + Expo
  if (config.headers) {
    config.headers["Accept"] = "application/json";
  }

  return config;
});

// Add response interceptor for better logging
httpClient.interceptors.response.use(
  (response) => {
    console.log(
      `Response from ${response.config.url}: status ${response.status}`
    );
    return response;
  },
  (error) => {
    if (error.response) {
      console.error(`Request failed with status: ${error.response.status}`);
    } else if (error.request) {
      console.error(`No response received: ${error.message}`);
    } else {
      console.error(`Request error: ${error.message}`);
    }
    return Promise.reject(error);
  }
);

export default httpClient;
