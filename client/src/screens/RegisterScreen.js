import "react-native-get-random-values"; // Mora biti prvi import
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
  ScrollView,
  Platform,
  ActivityIndicator,
  SafeAreaView,
  StatusBar,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import axios from "axios";
import * as SecureStore from "expo-secure-store";
import uuid from "react-native-uuid";
import * as Crypto from "expo-crypto";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import { Buffer } from "buffer";
// Import our enhanced randomness utilities
import enhancedRandom from "../utils/EnhancedRandom";
import serverEnhancedRandom from "../utils/ServerEnhancedRandom";
import CONFIG from "../config/config";

const RegisterScreen = ({ navigation }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [repeatPassword, setRepeatPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showRepeatPassword, setShowRepeatPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [serverEntropyAvailable, setServerEntropyAvailable] = useState(false);
  const [registerButtonDisabled, setRegisterButtonDisabled] = useState(false);

  // Initialize enhanced randomness systems when component mounts
  useEffect(() => {
    const initRandom = async () => {
      try {
        // Initialize local enhanced randomness
        await enhancedRandom.initialize();
        console.log("Local enhanced randomness initialized");

        // Initialize server-enhanced randomness
        await serverEnhancedRandom.initialize();
        const isAvailable =
          await serverEnhancedRandom.checkServerAvailability();
        setServerEntropyAvailable(isAvailable);
        console.log(
          `Server-enhanced randomness ${
            isAvailable ? "available" : "unavailable"
          }`
        );
      } catch (error) {
        console.error("Error initializing randomness systems:", error);
      }
    };

    initRandom();
  }, []);

  // Funkcija za sanitizaciju ključa
  const sanitizeKey = (key) => {
    return key.replace(/[^a-zA-Z0-9.-_]/g, "_");
  };

  // Funkcija za validaciju korisničkog imena
  const isValidUsername = (username) => {
    const regex = /^[a-zA-Z0-9.-_]+$/;
    return regex.test(username);
  };

  const generateSignalKeys = async () => {
    try {
      console.log("Starting Signal key generation process...");

      // Check server entropy availability here, don't rely on previous check
      let entropyServerAvailable = false;
      try {
        entropyServerAvailable =
          await serverEnhancedRandom.checkServerAvailability();
        console.log(
          `Entropy server check result: ${
            entropyServerAvailable ? "available" : "unavailable"
          }`
        );
      } catch (entropyCheckError) {
        console.log(
          "Error checking entropy server:",
          entropyCheckError.message
        );
        entropyServerAvailable = false;
      }

      // Force local randomness if there were any recent errors with the entropy server
      if (serverEntropyAvailable !== entropyServerAvailable) {
        console.log(
          `Updating server entropy availability from ${serverEntropyAvailable} to ${entropyServerAvailable}`
        );
        setServerEntropyAvailable(entropyServerAvailable);
      }

      // Log which entropy source we're using
      if (entropyServerAvailable) {
        console.log(
          "Attempting to generate Signal keys with SERVER-ENHANCED randomness"
        );
      } else {
        console.log(
          "Generating Signal keys with LOCAL-ENHANCED randomness (server unavailable)"
        );
      }

      // Sanitizacija korisničkog imena
      const sanitizedUsername = sanitizeKey(username);
      console.log(`Sanitized username: ${sanitizedUsername}`);

      // 1. Generisanje identitetskog ključa (identity key pair) - HIGHEST SECURITY PRIORITY
      console.log("1. Starting identity key pair generation...");
      let identityKeyPair;
      try {
        // Use server-enhanced randomness if available, otherwise fall back to local enhanced
        if (entropyServerAvailable) {
          try {
            identityKeyPair =
              await serverEnhancedRandom.generateIdentityKeyWithServerEntropy();
            console.log("Identity key pair generated with SERVER entropy");
          } catch (serverError) {
            console.log(
              "Server entropy failed, falling back to local:",
              serverError.message
            );
            identityKeyPair = await enhancedRandom.boxKeyPair();
            console.log("Identity key pair generated with LOCAL fallback");
          }
        } else {
          identityKeyPair = await enhancedRandom.boxKeyPair();
          console.log(
            "Identity key pair generated with LOCAL entropy (no server)"
          );
        }

        console.log("Identity key pair generated successfully:", {
          publicKeyLength: identityKeyPair.publicKey.length,
          privateKeyLength: identityKeyPair.secretKey.length,
        });
      } catch (error) {
        console.error("Identity key generation failed:", error);
        throw new Error(`Identity key generation failed: ${error.message}`);
      }

      // 2. Generisanje potpisnog ključa (signing key pair) - HIGH SECURITY PRIORITY
      console.log("2. Starting signing key pair generation...");
      let signingKeyPair;
      try {
        // Use server-enhanced randomness if available, otherwise fall back to local enhanced
        if (entropyServerAvailable) {
          try {
            signingKeyPair = await serverEnhancedRandom.signKeyPair();
            console.log("Signing key pair generated with SERVER entropy");
          } catch (serverError) {
            console.log(
              "Server entropy failed, falling back to local:",
              serverError.message
            );
            signingKeyPair = await enhancedRandom.signKeyPair();
            console.log("Signing key pair generated with LOCAL fallback");
          }
        } else {
          signingKeyPair = await enhancedRandom.signKeyPair();
          console.log(
            "Signing key pair generated with LOCAL entropy (no server)"
          );
        }

        console.log("Signing key pair generated successfully:", {
          publicKeyLength: signingKeyPair.publicKey.length,
          privateKeyLength: signingKeyPair.secretKey.length,
        });
      } catch (error) {
        console.error("Signing key generation failed:", error);
        throw new Error(`Signing key generation failed: ${error.message}`);
      }

      // 3. Generisanje potpisanog pre-ključa (signed pre-key) - MEDIUM SECURITY PRIORITY
      console.log("3. Generating signed pre-key...");
      const signedPreKeyId = 1;
      // Use local enhanced randomness for pre-keys (acceptable security/performance trade-off)
      const signedPreKeyPair = await enhancedRandom.boxKeyPair();
      console.log("Signed pre-key pair generated:", {
        publicKeyLength: signedPreKeyPair.publicKey.length,
        privateKeyLength: signedPreKeyPair.secretKey.length,
      });

      // 4. Potpisivanje signed pre-key javnog ključa
      console.log("4. Generating signed pre-key signature...");
      const signedPreKeySignature = nacl.sign.detached(
        signedPreKeyPair.publicKey,
        signingKeyPair.secretKey
      );
      console.log("Signed pre-key signature generated:", {
        signatureLength: signedPreKeySignature.length,
      });

      // 5. Generisanje jednokratnih pre-ključeva (one-time pre-keys) - LOWER SECURITY PRIORITY
      console.log("5. Generating one-time pre-keys...");
      const oneTimePreKeys = [];
      for (let i = 1; i <= 30; i++) {
        // For one-time keys, we can use standard randomness as there are many of these
        // and they're less critical (for performance reasons)
        const keyPair = nacl.box.keyPair();
        console.log(`One-time pre-key ${i} generated:`, {
          publicKeyLength: keyPair.publicKey.length,
          privateKeyLength: keyPair.secretKey.length,
        });
        oneTimePreKeys.push({
          keyId: i,
          keyPair,
        });
      }
      console.log("One-time pre-keys generated:", oneTimePreKeys.length);

      // Konvertovanje ključeva u base64
      console.log("6. Converting keys to base64...");
      const identityKeyPublic = naclUtil.encodeBase64(
        identityKeyPair.publicKey
      );
      const identityKeyPrivate = naclUtil.encodeBase64(
        identityKeyPair.secretKey
      );
      console.log(`Identity key public: ${identityKeyPublic}`);
      console.log(`Identity key private: ${identityKeyPrivate}`);

      const signingKeyPublic = naclUtil.encodeBase64(signingKeyPair.publicKey);
      const signingKeyPrivate = naclUtil.encodeBase64(signingKeyPair.secretKey);
      console.log(`Signing key public: ${signingKeyPublic}`);
      console.log(`Signing key private: ${signingKeyPrivate}`);

      const signedPreKeyPublic = naclUtil.encodeBase64(
        signedPreKeyPair.publicKey
      );
      const signedPreKeyPrivate = naclUtil.encodeBase64(
        signedPreKeyPair.secretKey
      );
      console.log(`Signed pre-key public: ${signedPreKeyPublic}`);
      console.log(`Signed pre-key private: ${signedPreKeyPrivate}`);

      const signedPreKeySignatureBase64 = naclUtil.encodeBase64(
        signedPreKeySignature
      );
      console.log(`Signed pre-key signature: ${signedPreKeySignatureBase64}`);

      const oneTimePreKeysPublic = oneTimePreKeys.map((key) => ({
        keyId: key.keyId,
        publicKey: naclUtil.encodeBase64(key.keyPair.publicKey),
      }));
      const oneTimePreKeysPrivate = oneTimePreKeys.map((key) => ({
        keyId: key.keyId,
        privateKey: naclUtil.encodeBase64(key.keyPair.secretKey),
      }));
      console.log("One-time pre-keys public:");
      oneTimePreKeysPublic.forEach((key) =>
        console.log(` - Key ID ${key.keyId}: ${key.publicKey}`)
      );
      console.log("One-time pre-keys private:");
      oneTimePreKeysPrivate.forEach((key) =>
        console.log(` - Key ID ${key.keyId}: ${key.privateKey}`)
      );

      // Store randomness source information for auditing
      const randomnessSourceInfo = {
        identityKey: serverEntropyAvailable
          ? "server-enhanced"
          : "local-enhanced",
        signingKey: serverEntropyAvailable
          ? "server-enhanced"
          : "local-enhanced",
        signedPreKey: "local-enhanced",
        oneTimePreKeys: "standard",
        timestamp: new Date().toISOString(),
      };
      await SecureStore.setItemAsync(
        `${sanitizedUsername}_entropy_sources`,
        JSON.stringify(randomnessSourceInfo)
      );

      // Čuvanje privatnih ključeva u SecureStore sa sanitiziranim korisničkim imenom
      console.log("7. Saving private keys to SecureStore...");
      await SecureStore.setItemAsync(
        `${sanitizedUsername}_identityKeyPrivate`,
        identityKeyPrivate
      );
      await SecureStore.setItemAsync(
        `${sanitizedUsername}_signingKeyPrivate`,
        signingKeyPrivate
      );
      await SecureStore.setItemAsync(
        `${sanitizedUsername}_signedPreKeyPrivate`,
        signedPreKeyPrivate
      );
      await SecureStore.setItemAsync(
        `${sanitizedUsername}_oneTimePreKeysPrivate`,
        JSON.stringify(oneTimePreKeysPrivate)
      );
      console.log("Private keys saved to SecureStore");

      console.log("8. Signal keys generated successfully");
      return {
        identityKeyPublic,
        signingKeyPublic,
        signedPreKeyPublic,
        signedPreKeyId,
        signedPreKeySignature: signedPreKeySignatureBase64,
        oneTimePreKeysPublic,
      };
    } catch (error) {
      console.error("Signal keys generation failed:", error);
      throw new Error(`Failed to generate Signal keys: ${error.message}`);
    }
  };

  const handleRegister = async () => {
    // Prevent multiple button presses
    if (isLoading || registerButtonDisabled) {
      return;
    }

    setIsLoading(true);
    setRegisterButtonDisabled(true);

    console.log("1. Register button clicked:", {
      username,
      password,
      repeatPassword,
    });

    // Validacija unosa
    if (!username || !password || !repeatPassword) {
      Alert.alert("Error", "Please fill in all fields");
      setIsLoading(false);
      console.log("2. Validation failed: Missing fields");
      return;
    }

    if (!isValidUsername(username)) {
      Alert.alert(
        "Invalid Username",
        "Username can only contain letters, numbers, '.', '-', and '_'. Please choose a different username."
      );
      setIsLoading(false);
      console.log("3. Validation failed: Invalid username characters");
      return;
    }

    if (password !== repeatPassword) {
      Alert.alert("Error", "Passwords do not match");
      setIsLoading(false);
      console.log("4. Validation failed: Passwords do not match");
      return;
    }

    // Generisanje deviceId-a
    let deviceId;
    try {
      console.log("5. Generating deviceId...");
      deviceId = uuid.v4();
      console.log("6. Generated deviceId:", deviceId);
    } catch (error) {
      Alert.alert("Error", "Failed to generate device ID");
      setIsLoading(false);
      console.error("7. DeviceId generation error:", error);
      return;
    }

    // Heširanje lozinke
    let hashedPassword;
    try {
      console.log("8. Hashing password...");
      const salt = nacl.randomBytes(16);
      const saltBase64 = naclUtil.encodeBase64(salt);
      console.log("Salt generated:", saltBase64);
      hashedPassword = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        password,
        {
          encoding: Crypto.CryptoEncoding.BASE64,
          salt: Buffer.from(salt),
          iterations: 100000,
          keyLength: 32,
        }
      );
      hashedPassword = saltBase64 + hashedPassword;
      console.log("9. Password hashed:", hashedPassword);
    } catch (error) {
      Alert.alert("Error", "Failed to hash password");
      setIsLoading(false);
      console.error("10. Password hashing error:", error);
      return;
    }

    // Generisanje Signal ključeva
    let signalKeys;
    try {
      console.log("11. Generating Signal keys...");
      signalKeys = await generateSignalKeys();
      console.log("12. Signal keys generated:", {
        identityKeyPublic: signalKeys.identityKeyPublic,
        signingKeyPublic: signalKeys.signingKeyPublic,
        signedPreKeyPublic: signalKeys.signedPreKeyPublic,
        signedPreKeyId: signalKeys.signedPreKeyId,
        signedPreKeySignature: signalKeys.signedPreKeySignature,
        oneTimePreKeysPublic: signalKeys.oneTimePreKeysPublic,
      });
    } catch (error) {
      Alert.alert("Error", error.message);
      setIsLoading(false);
      console.error("13. Signal keys generation error:", error);
      return;
    }

    // Slanje zahteva na server
    try {
      console.log(
        "14. Sending request to backend:",
        `${CONFIG.BACKEND_URL}/api/users/register`,
        `(with ${Math.floor(signalKeys.oneTimePreKeysPublic.length)} pre-keys)`
      );
      console.log(`Request timeout set to: ${180000 / 1000} seconds`);

      const startTime = Date.now();
      console.log("Request started at:", new Date(startTime).toISOString());

      const response = await axios.post(
        `${CONFIG.BACKEND_URL}/api/users/register`,
        {
          username,
          deviceId,
          identityKeyPublic: signalKeys.identityKeyPublic,
          signingKeyPublic: signalKeys.signingKeyPublic,
          signedPreKeyPublic: signalKeys.signedPreKeyPublic,
          signedPreKeyId: signalKeys.signedPreKeyId,
          signedPreKeySignature: signalKeys.signedPreKeySignature,
          oneTimePreKeysPublic: signalKeys.oneTimePreKeysPublic,
        },
        { timeout: 180000 }
      );

      const endTime = Date.now();
      console.log("Request completed at:", new Date(endTime).toISOString());
      console.log(
        `Request took ${(endTime - startTime) / 1000} seconds to complete`
      );

      console.log("15. Backend response:", response.data);

      // Čuvanje kredencijala u SecureStore
      try {
        console.log("16. Saving credentials to SecureStore...");
        await SecureStore.setItemAsync("username", username);
        await SecureStore.setItemAsync("deviceId", deviceId);
        await SecureStore.setItemAsync("passwordHash", hashedPassword);
        console.log("17. Credentials saved to SecureStore");
      } catch (storageError) {
        console.error("18. SecureStore error:", storageError.message);
        Alert.alert(
          "Warning",
          "Registered successfully, but failed to save credentials locally. You can still log in."
        );
      }

      Alert.alert("Success", "Registration successful! Please log in.", [
        {
          text: "OK",
          onPress: () => {
            console.log("19. Navigating to Login");
            navigation.navigate("Login", { justRegistered: true });
          },
        },
      ]);
    } catch (error) {
      let errorMessage = "Something went wrong";

      console.log("Registration error details:", {
        hasResponse: Boolean(error.response),
        status: error.response?.status,
        data: error.response?.data,
        error: error.message,
      });

      if (error.response) {
        // Check specifically for username existing error
        if (error.response.data?.error === "Username already exists") {
          errorMessage =
            "Username already taken. Please choose a different username.";
          console.log("Username already exists error detected");
        } else {
          errorMessage =
            error.response.data?.error ||
            `Server error: ${error.response.status}`;
          console.log("Other server error:", errorMessage);
        }
      } else if (error.request) {
        errorMessage = "No response from server. Check network or server URL.";
        console.log("No response from server");
      } else {
        errorMessage = error.message;
        console.log("Request setup error:", error.message);
      }

      // Ensure alert is called with await to make sure it's shown
      console.log("Showing alert with message:", errorMessage);
      Alert.alert("Registration Failed", errorMessage, [{ text: "OK" }], {
        cancelable: false,
      });
    } finally {
      setIsLoading(false);
      // Re-enable the button after a short delay to prevent accidental double taps
      setTimeout(() => {
        setRegisterButtonDisabled(false);
      }, 1000);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#252762" />
      <KeyboardAvoidingView
        style={styles.keyboardContainer}
        behavior={Platform.OS === "ios" ? "padding" : "height"}
        keyboardVerticalOffset={Platform.OS === "ios" ? 40 : 0}
        contentContainerStyle={{ flex: 1 }}
      >
        <ScrollView
          contentContainerStyle={styles.content}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
          bounces={false}
        >
          <View style={styles.logoContainer}>
            <Image
              source={require("../../assets/logo.png")}
              style={styles.logo}
            />
          </View>

          <View style={styles.formContainer}>
            <Text style={styles.title}>Create Account</Text>

            <View style={styles.inputContainer}>
              <TextInput
                style={styles.input}
                placeholder="Enter username"
                placeholderTextColor="#888"
                value={username}
                onChangeText={setUsername}
                autoCapitalize="none"
              />
            </View>

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

            <View style={styles.inputContainer}>
              <View style={styles.passwordContainer}>
                <TextInput
                  style={[styles.input, styles.passwordInput]}
                  placeholder="Repeat password"
                  placeholderTextColor="#888"
                  secureTextEntry={!showRepeatPassword}
                  value={repeatPassword}
                  onChangeText={setRepeatPassword}
                />
                <TouchableOpacity
                  style={styles.eyeButton}
                  onPress={() => setShowRepeatPassword(!showRepeatPassword)}
                >
                  <Ionicons
                    name={showRepeatPassword ? "eye-off" : "eye"}
                    size={24}
                    color="#888"
                  />
                </TouchableOpacity>
              </View>
            </View>

            <TouchableOpacity
              style={[
                styles.button,
                (isLoading || registerButtonDisabled) && styles.buttonDisabled,
              ]}
              onPress={handleRegister}
              disabled={isLoading || registerButtonDisabled}
            >
              {isLoading ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.buttonText}>Register</Text>
              )}
            </TouchableOpacity>
          </View>
        </ScrollView>
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
    flexGrow: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: 30,
    paddingTop: 20,
    paddingBottom: Platform.OS === "ios" ? 80 : 60,
  },
  logoContainer: {
    alignItems: "center",
    marginTop: Platform.OS === "ios" ? 20 : 10,
    marginBottom: 20,
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
  input: {
    color: "#ffffff",
    paddingVertical: 16,
    paddingHorizontal: 15,
    fontSize: 16,
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    borderRadius: 12,
  },
  passwordContainer: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    borderRadius: 12,
    paddingHorizontal: 15,
  },
  passwordInput: {
    flex: 1,
    paddingHorizontal: 0,
    backgroundColor: "transparent",
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
    borderBottomWidth: 1,
    borderBottomColor: "#fff",
  },
  footer: {
    backgroundColor: "#1a1a1d",
    height: 60,
    width: "100%",
    position: "absolute",
    bottom: 0,
    left: 0,
    right: 0,
    borderTopWidth: 1,
    borderTopColor: "#fff",
  },
});

export default RegisterScreen;
