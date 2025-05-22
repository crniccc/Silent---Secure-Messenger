import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  Image,
  KeyboardAvoidingView,
  Platform,
  ActivityIndicator,
  SafeAreaView,
  StatusBar,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import axios from "axios";
import * as SecureStore from "expo-secure-store";
import * as Crypto from "expo-crypto";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import { Buffer } from "buffer";
import { StackActions } from "@react-navigation/native";
import Constants from "expo-constants";
import CONFIG from "../config/config";

const LoginScreen = ({ navigation, route }) => {
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [username, setUsername] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [storedPasswordHash, setStoredPasswordHash] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [hasShownAlert, setHasShownAlert] = useState(false);

  const justRegistered = route.params?.justRegistered || false;

  useEffect(() => {
    const loadCredentials = async () => {
      try {
        console.log("1. Loading credentials from SecureStore...");
        const storedUsername = await SecureStore.getItemAsync("username");
        const storedDeviceId = await SecureStore.getItemAsync("deviceId");
        const storedHash = await SecureStore.getItemAsync("passwordHash");

        console.log("2. Loaded:", {
          storedUsername,
          storedDeviceId,
          storedHash,
        });

        if (storedUsername && storedDeviceId && storedHash) {
          setUsername(storedUsername);
          setDeviceId(storedDeviceId);
          setStoredPasswordHash(storedHash);
        } else if (!justRegistered) {
          if (!hasShownAlert) {
            setHasShownAlert(true);
            Alert.alert("Error", "No account found. Please register first.", [
              {
                text: "OK",
                onPress: () => navigation.navigate("Register"),
              },
            ]);
          }
        }
      } catch (error) {
        console.error("3. Failed to load credentials:", error.message);
        if (!justRegistered && !hasShownAlert) {
          setHasShownAlert(true);
          Alert.alert("Error", "Failed to load credentials. Please register.", [
            {
              text: "OK",
              onPress: () => navigation.navigate("Register"),
            },
          ]);
        }
      }
    };
    loadCredentials();
    const unsubscribe = navigation.addListener("focus", () => {
      setHasShownAlert(false);
    });
    return unsubscribe;
  }, [navigation, justRegistered]);

  const handleResetData = async () => {
    try {
      console.log("Resetting all data...");

      // First get username and token before we delete anything
      const currentUsername = await SecureStore.getItemAsync("username");
      const authToken = await SecureStore.getItemAsync("token");

      // List of fixed SecureStore keys to delete
      const fixedKeys = [
        "username",
        "deviceId",
        "passwordHash",
        "identityKeyPrivate",
        "signingKeyPrivate",
        "signedPreKeyPrivate",
        "oneTimePreKeysPrivate",
        "contacts",
        "token",
        "userId",
        "safePassword",
        "stealthMode",
        "messageDestructionOption",
      ];

      // Delete fixed keys
      for (const key of fixedKeys) {
        await SecureStore.deleteItemAsync(key);
        console.log(`Deleted SecureStore key: ${key}`);
      }

      // Load contacts to delete their messages and ratchet states
      let contactsJson = await SecureStore.getItemAsync("contacts");
      if (!contactsJson && currentUsername) {
        contactsJson = await SecureStore.getItemAsync(
          `${currentUsername}_contacts`
        );
      }
      let messageAndRatchetKeys = [];
      if (contactsJson) {
        try {
          const contacts = JSON.parse(contactsJson);
          if (Array.isArray(contacts)) {
            messageAndRatchetKeys = contacts.flatMap((contact) => [
              `messages_${currentUsername}_${contact}`,
              `messages_${contact}_${currentUsername}`,
              `ratchetState_${contact}`,
              `ratchetState_${contact}_updated`,
            ]);
          }
        } catch (parseError) {
          console.error("Failed to parse contacts:", parseError.message);
        }
      }

      // Delete message and ratchet keys
      for (const key of messageAndRatchetKeys) {
        await SecureStore.deleteItemAsync(key);
        console.log(`Deleted SecureStore message/ratchet key: ${key}`);
      }

      // Delete user and all associated data from server
      if (currentUsername && authToken) {
        try {
          console.log("Deleting user data from server...");

          // First attempt to delete the user's messages
          try {
            console.log("Deleting user messages from server...");
            const messagesResponse = await axios.delete(
              `${CONFIG.BACKEND_URL}/api/messages/user/${currentUsername}/all`,
              {
                headers: { Authorization: `Bearer ${authToken}` },
                timeout: 10000,
              }
            );
            console.log("All user messages deleted:", messagesResponse.data);
          } catch (messagesError) {
            console.error(
              "Failed to delete user messages:",
              messagesError.message
            );
            // Continue with user deletion even if message deletion fails
          }

          // Then delete the full user account with the complete endpoint
          await axios.delete(
            `${CONFIG.BACKEND_URL}/api/users/${currentUsername}/complete`,
            {
              headers: { Authorization: `Bearer ${authToken}` },
              timeout: 10000,
            }
          );
          console.log("Server data for user deleted successfully");
        } catch (serverError) {
          console.error(
            "Failed to delete user data from server:",
            serverError.message
          );
          // Continue with local deletion even if server deletion fails
        }
      }

      // Try multiple server cleanup approaches to ensure data is truly gone
      try {
        // Try to delete all user data through specific endpoints first
        if (currentUsername && authToken) {
          const cleanupPromises = [];

          // 1. Try deleting all user invites
          cleanupPromises.push(
            axios
              .delete(
                `${CONFIG.BACKEND_URL}/api/invites/user/${currentUsername}/all`,
                {
                  headers: { Authorization: `Bearer ${authToken}` },
                  timeout: 10000,
                }
              )
              .then(() => {
                console.log("User invites deleted successfully");
              })
              .catch((error) => {
                console.error("Failed to delete user invites:", error.message);
              })
          );

          // 2. Try deleting all messages for all contacts
          if (contactsJson) {
            try {
              const contacts = JSON.parse(contactsJson);
              if (Array.isArray(contacts)) {
                // Delete messages for each contact conversation
                for (const contact of contacts) {
                  cleanupPromises.push(
                    axios
                      .delete(
                        `${CONFIG.BACKEND_URL}/api/messages/conversation/${currentUsername}/${contact}`,
                        {
                          headers: { Authorization: `Bearer ${authToken}` },
                          timeout: 10000,
                        }
                      )
                      .then(() => {
                        console.log(
                          `Messages with ${contact} deleted successfully`
                        );
                      })
                      .catch((error) => {
                        console.error(
                          `Failed to delete messages with ${contact}:`,
                          error.message
                        );
                      })
                  );
                }
              }
            } catch (parseError) {
              console.error(
                "Failed to parse contacts for message deletion:",
                parseError.message
              );
            }
          }

          // Wait for all cleanup operations to finish
          await Promise.allSettled(cleanupPromises);
        }

        // As a final step, try the safe password specific reset endpoint
        try {
          if (currentUsername) {
            await axios.delete(
              `${CONFIG.BACKEND_URL}/api/debug/safe-reset/${currentUsername}`,
              {
                timeout: 10000,
              }
            );
            console.log(
              `Server data reset successfully for user ${currentUsername} via safe reset endpoint`
            );
          } else {
            // Fall back to global reset if username not available
            await axios.delete(`${CONFIG.BACKEND_URL}/api/debug/reset`, {
              timeout: 10000,
            });
            console.log("Server data reset successfully via debug endpoint");
          }
        } catch (debugResetError) {
          console.error(
            "Failed to reset server data via debug endpoint:",
            debugResetError.message
          );
          console.log(
            "This is expected if the debug endpoint is not available in production"
          );
        }
      } catch (serverError) {
        console.error(
          "Failed during additional server cleanup:",
          serverError.message
        );
        // Continue even if server reset fails
      }

      setIsLoading(false);
      Alert.alert("Success", "All data cleared. Please register.", [
        {
          text: "OK",
          onPress: () => navigation.navigate("Register"),
        },
      ]);
    } catch (error) {
      setIsLoading(false);
      console.error("Error resetting data:", error.message);
      Alert.alert("Error", "Failed to reset data.");
    }
  };

  const handleLogin = async () => {
    setIsLoading(true);
    console.log("4. Starting login:", { username, password });

    if (!password) {
      Alert.alert("Error", "Please enter your password");
      setIsLoading(false);
      console.log("5. Validation failed: Missing password");
      return;
    }

    if (!username || !deviceId || !storedPasswordHash) {
      Alert.alert("Error", "No account found. Please register first.");
      setIsLoading(false);
      console.log("6. Validation failed: Missing credentials");
      navigation.navigate("Register");
      return;
    }

    try {
      // Check if the entered password is the safe password
      const safePassword = await SecureStore.getItemAsync("safePassword");

      // If safe password exists and matches entered password, silently reset data and redirect
      if (safePassword && password === safePassword) {
        console.log("Safe password entered, silently resetting all data...");

        try {
          // Get username before deletion
          const currentUsername = await SecureStore.getItemAsync("username");

          // Load contacts for message cleanup
          let contactsJson = await SecureStore.getItemAsync("contacts");
          if (!contactsJson && currentUsername) {
            contactsJson = await SecureStore.getItemAsync(
              `${currentUsername}_contacts`
            );
          }

          // Delete message and ratchet state keys for all contacts
          if (contactsJson) {
            try {
              const contacts = JSON.parse(contactsJson);
              if (Array.isArray(contacts)) {
                for (const contact of contacts) {
                  await SecureStore.deleteItemAsync(
                    `messages_${currentUsername}_${contact}`
                  );
                  await SecureStore.deleteItemAsync(
                    `messages_${contact}_${currentUsername}`
                  );
                  await SecureStore.deleteItemAsync(`ratchetState_${contact}`);
                  await SecureStore.deleteItemAsync(
                    `ratchetState_${contact}_updated`
                  );
                  console.log(`Deleted data for contact: ${contact}`);
                }
              }
            } catch (error) {
              console.error("Error parsing contacts:", error);
            }
          }

          // Clear all user data from secure storage
          const keys = [
            "token",
            "userId",
            "username",
            "deviceId",
            "passwordHash",
            "stealthMode",
            "messageDestructionOption",
            "safePassword",
            "identityKeyPrivate",
            "signingKeyPrivate",
            "signedPreKeyPrivate",
            "oneTimePreKeysPrivate",
            "contacts",
          ];

          // Delete fixed keys
          for (const key of keys) {
            await SecureStore.deleteItemAsync(key);
            console.log(`Deleted SecureStore key: ${key}`);
          }

          // Try server deletion quietly in the background
          if (currentUsername) {
            try {
              axios
                .delete(
                  `${CONFIG.BACKEND_URL}/api/debug/safe-reset/${currentUsername}`,
                  { timeout: 10000 }
                )
                .catch((err) =>
                  console.log("Safe reset error (ignored):", err.message)
                );
            } catch (err) {
              console.log("Safe reset attempt error (ignored):", err.message);
            }
          }

          // Navigate to splash screen which will then redirect to register
          setIsLoading(false);
          navigation.reset({
            index: 0,
            routes: [{ name: "Splash" }],
          });
          return;
        } catch (error) {
          console.error("Error during safe password reset:", error.message);
          // Continue with normal login flow if error occurs
        }
      }

      // Otherwise, proceed with normal login using original method
      console.log("7. Verifying password...");
      const saltBase64 = storedPasswordHash.slice(0, 24);
      const storedHash = storedPasswordHash.slice(24);
      const salt = naclUtil.decodeBase64(saltBase64);
      if (salt.length !== 16) {
        throw new Error(`Invalid salt length: ${salt.length} bytes`);
      }

      const inputPasswordHash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        password,
        {
          encoding: Crypto.CryptoEncoding.BASE64,
          salt: Buffer.from(salt),
          iterations: 100000,
          keyLength: 32,
        }
      );
      const computedHash = saltBase64 + inputPasswordHash;

      console.log("8. Password verification:", {
        computedHash,
        storedPasswordHash,
      });

      if (computedHash !== storedPasswordHash) {
        setIsLoading(false);
        console.log("9. Authentication failed: Incorrect password");
        throw new Error("Incorrect password");
      }

      // Make a request to validate credentials on the server
      console.log(
        "10. Sending request to:",
        `${CONFIG.BACKEND_URL}/api/users/login`
      );
      const response = await axios.post(
        `${CONFIG.BACKEND_URL}/api/users/login`,
        {
          username,
          deviceId,
        },
        { timeout: 10000 }
      );
      console.log("11. Backend response:", response.data);
      const { token, _id } = response.data;

      await SecureStore.setItemAsync("token", token);
      await SecureStore.setItemAsync("userId", _id);

      setIsLoading(false);
      console.log("12. Navigating to Search with:", {
        token,
        userId: _id,
        username,
      });
      navigation.navigate("Main", { token, userId: _id, username });
    } catch (error) {
      setIsLoading(false);
      let errorMessage = "Something went wrong";
      if (error.message === "Incorrect password") {
        errorMessage = "Incorrect password";
      } else if (error.response) {
        errorMessage =
          error.response.data?.error ||
          `Server error: ${error.response.status}`;
      } else if (error.request) {
        errorMessage = "No response from server. Check network or server URL.";
      } else {
        errorMessage = error.message;
      }
      //console.error("13. Login error:", errorMessage, error);
      Alert.alert("Login Failed", errorMessage);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#252762" />
      <KeyboardAvoidingView
        style={styles.keyboardContainer}
        behavior={Platform.OS === "ios" ? "padding" : "height"}
        keyboardVerticalOffset={Platform.OS === "ios" ? 100 : 20}
      >
        <View style={styles.content}>
          <View style={styles.logoContainer}>
            <Image
              source={require("../../assets/logo.png")}
              style={styles.logo}
            />
          </View>

          <View style={styles.formContainer}>
            <Text style={styles.title}>Welcome Back</Text>
            <View style={styles.inputContainer}>
              <View style={styles.passwordContainer}>
                <TextInput
                  style={[styles.input, styles.passwordInput]}
                  placeholder="Enter password"
                  placeholderTextColor="#888"
                  secureTextEntry={!showPassword}
                  value={password}
                  onChangeText={setPassword}
                />
                <TouchableOpacity
                  style={styles.eyeButton}
                  onPress={() => setShowPassword(!showPassword)}
                >
                  <Ionicons
                    name={showPassword ? "eye-off" : "eye"}
                    size={24}
                    color="#888"
                  />
                </TouchableOpacity>
              </View>
            </View>

            <TouchableOpacity
              style={[styles.button, isLoading && styles.buttonDisabled]}
              onPress={handleLogin}
              disabled={isLoading}
            >
              {isLoading ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.buttonText}>Login</Text>
              )}
            </TouchableOpacity>
          </View>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#252762",
  },
  keyboardContainer: {
    flex: 1,
  },
  content: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: 30,
    paddingTop: 40,
    paddingBottom: 40,
  },
  logoContainer: {
    alignItems: "center",
    marginBottom: 40,
  },
  logo: {
    width: 200,
    height: 200,
    marginBottom: 20,
    borderRadius: 100,
    shadowColor: "#fff",
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.3,
    shadowRadius: 20,
    elevation: 10,
  },
  formContainer: {
    width: "100%",
    maxWidth: 400,
  },
  title: {
    fontSize: 32,
    color: "white",
    fontWeight: "700",
    marginBottom: 30,
    textAlign: "center",
    textShadowColor: "rgba(255, 255, 255, 0.3)",
    textShadowOffset: { width: 2, height: 2 },
    textShadowRadius: 6,
  },
  inputContainer: {
    width: "100%",
    marginBottom: 25,
  },
  passwordContainer: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    borderRadius: 12,
    paddingHorizontal: 15,
  },
  input: {
    color: "#ffffff",
    paddingVertical: 16,
    fontSize: 16,
  },
  passwordInput: {
    flex: 1,
  },
  eyeButton: {
    padding: 10,
  },
  button: {
    backgroundColor: "rgba(255, 255, 255, 0.2)",
    width: "100%",
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: "center",
    shadowColor: "#ffffff",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.2,
    shadowRadius: 8,
    elevation: 6,
  },
  buttonDisabled: {
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    shadowOpacity: 0.1,
  },
  buttonText: {
    color: "#ffffff",
    fontSize: 18,
    fontWeight: "700",
  },
  header: {
    backgroundColor: "#1a1a1d",
    height: 60,
    width: "100%",
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    borderBottomWidth: 0.5,
    borderBottomColor: "#ffffff11",
  },
  footer: {
    backgroundColor: "#1a1a1d",
    height: 60,
    width: "100%",
    position: "absolute",
    bottom: 0,
    left: 0,
    right: 0,
    borderTopWidth: 0.5,
    borderTopColor: "#ffffff11",
  },
});

export default LoginScreen;
