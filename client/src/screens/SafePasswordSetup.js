import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  Alert,
  TextInput,
  ActivityIndicator,
} from "react-native";
import { useNavigation } from "@react-navigation/native";
import { Ionicons } from "@expo/vector-icons";
import * as SecureStore from "expo-secure-store";
import * as Crypto from "expo-crypto";
import axios from "axios";
import { Buffer } from "buffer";
import naclUtil from "tweetnacl-util";
import CONFIG from "../config/config";

const SafePasswordSetup = () => {
  const navigation = useNavigation();
  const [safePassword, setSafePassword] = useState("");
  const [confirmSafePassword, setConfirmSafePassword] = useState("");
  const [showSafePassword, setShowSafePassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [hasSafePassword, setHasSafePassword] = useState(false);

  useEffect(() => {
    const checkSafePassword = async () => {
      const storedSafePassword = await SecureStore.getItemAsync("safePassword");
      setHasSafePassword(!!storedSafePassword);
    };
    checkSafePassword();
  }, []);

  const handleSetup = async () => {
    if (safePassword !== confirmSafePassword) {
      Alert.alert("Error", "Passwords do not match");
      return;
    }

    if (safePassword.length < 4) {
      Alert.alert("Error", "Password must be at least 4 characters");
      return;
    }

    setIsLoading(true);

    try {
      // Generate a salt for the password
      const salt = Buffer.from(
        naclUtil.decodeBase64(
          naclUtil.encodeBase64(Buffer.from(Crypto.getRandomBytes(16)))
        )
      );
      const saltBase64 = naclUtil.encodeBase64(salt);

      // Hash the password with the salt
      const hashedPassword = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        safePassword,
        {
          encoding: Crypto.CryptoEncoding.BASE64,
          salt: salt,
          iterations: 100000,
          keyLength: 32,
        }
      );

      // Store the salted hash
      const saltedHash = saltBase64 + hashedPassword;
      await SecureStore.setItemAsync("safePassword", saltedHash);

      Alert.alert(
        "Success",
        "Safe password set successfully. When entered during login, this password will delete all your data.",
        [{ text: "OK", onPress: () => navigation.goBack() }]
      );
    } catch (error) {
      Alert.alert("Error", "Failed to set safe password");
      console.error("Safe password setup error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRemoveSafePassword = async () => {
    try {
      await SecureStore.deleteItemAsync("safePassword");
      setHasSafePassword(false);
      Alert.alert("Success", "Safe password removed");
    } catch (error) {
      Alert.alert("Error", "Failed to remove safe password");
      console.error("Safe password removal error:", error);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={24} color="white" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Safe Password Setup</Text>
      </View>
      <View style={styles.content}>
        <Text style={styles.description}>
          Set a password that will permanently delete your account when entered
          at the login screen. This provides a way to quickly remove all your
          data in case of emergency.
        </Text>

        {hasSafePassword ? (
          <>
            <Text style={styles.passwordSetText}>
              Safe password is currently set
            </Text>
            <TouchableOpacity
              style={styles.removeButton}
              onPress={handleRemoveSafePassword}
            >
              <Text style={styles.removeButtonText}>Remove Safe Password</Text>
            </TouchableOpacity>
          </>
        ) : (
          <>
            <View style={styles.inputContainer}>
              <Text style={styles.label}>Safe Password:</Text>
              <View style={styles.passwordContainer}>
                <TextInput
                  style={styles.input}
                  placeholder="Enter safe password"
                  placeholderTextColor="#888"
                  secureTextEntry={!showSafePassword}
                  value={safePassword}
                  onChangeText={setSafePassword}
                />
                <TouchableOpacity
                  style={styles.eyeButton}
                  onPress={() => setShowSafePassword(!showSafePassword)}
                >
                  <Ionicons
                    name={showSafePassword ? "eye-off" : "eye"}
                    size={24}
                    color="#888"
                  />
                </TouchableOpacity>
              </View>
            </View>

            <View style={styles.inputContainer}>
              <Text style={styles.label}>Confirm Safe Password:</Text>
              <View style={styles.passwordContainer}>
                <TextInput
                  style={styles.input}
                  placeholder="Confirm safe password"
                  placeholderTextColor="#888"
                  secureTextEntry={!showConfirmPassword}
                  value={confirmSafePassword}
                  onChangeText={setConfirmSafePassword}
                />
                <TouchableOpacity
                  style={styles.eyeButton}
                  onPress={() => setShowConfirmPassword(!showConfirmPassword)}
                >
                  <Ionicons
                    name={showConfirmPassword ? "eye-off" : "eye"}
                    size={24}
                    color="#888"
                  />
                </TouchableOpacity>
              </View>
            </View>

            <TouchableOpacity
              style={[styles.button, isLoading && styles.buttonDisabled]}
              onPress={handleSetup}
              disabled={isLoading}
            >
              {isLoading ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.buttonText}>Set Safe Password</Text>
              )}
            </TouchableOpacity>
          </>
        )}
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#0F0F0F",
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    padding: 15,
    backgroundColor: "#252762",
  },
  headerTitle: {
    color: "white",
    fontSize: 18,
    fontWeight: "bold",
    marginLeft: 15,
  },
  content: {
    flex: 1,
    padding: 20,
  },
  description: {
    color: "white",
    fontSize: 16,
    textAlign: "center",
    marginBottom: 30,
  },
  inputContainer: {
    marginBottom: 20,
  },
  label: {
    color: "white",
    fontSize: 16,
    fontWeight: "600",
    marginBottom: 8,
  },
  passwordContainer: {
    flexDirection: "row",
    alignItems: "center",
  },
  input: {
    flex: 1,
    backgroundColor: "#252525",
    color: "white",
    paddingHorizontal: 15,
    paddingVertical: 12,
    borderRadius: 8,
    fontSize: 16,
    borderWidth: 1,
    borderColor: "#444",
  },
  eyeButton: {
    position: "absolute",
    right: 10,
    padding: 10,
  },
  button: {
    backgroundColor: "#4A80F0",
    paddingVertical: 15,
    borderRadius: 10,
    alignItems: "center",
  },
  buttonDisabled: {
    backgroundColor: "#555",
  },
  buttonText: {
    color: "white",
    fontSize: 16,
    fontWeight: "600",
  },
  passwordSetText: {
    color: "#4A80F0",
    fontSize: 18,
    textAlign: "center",
    marginBottom: 20,
  },
  removeButton: {
    backgroundColor: "#FF3B30",
    paddingVertical: 15,
    borderRadius: 10,
    alignItems: "center",
  },
  removeButtonText: {
    color: "white",
    fontSize: 16,
    fontWeight: "600",
  },
});

export default SafePasswordSetup;
