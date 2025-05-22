import React, { useState } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  Alert,
  ActivityIndicator,
  TextInput,
} from "react-native";
import { useNavigation } from "@react-navigation/native";
import { Ionicons } from "@expo/vector-icons";
import * as SecureStore from "expo-secure-store";
import axios from "axios";
import CONFIG from "../config/config";

const DeleteConfirmation = () => {
  const navigation = useNavigation();
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleDelete = async () => {
    if (!password) {
      Alert.alert("Error", "Please enter your password to confirm deletion");
      return;
    }

    setIsLoading(true);

    try {
      const username = await SecureStore.getItemAsync("username");
      const storedPasswordHash = await SecureStore.getItemAsync("passwordHash");
      const token = await SecureStore.getItemAsync("token");

      if (!username || !storedPasswordHash || !token) {
        throw new Error("Required credentials not found");
      }

      // Verify password
      const isValid = await verifyPassword(password, storedPasswordHash);
      if (!isValid) {
        Alert.alert("Error", "Incorrect password");
        setIsLoading(false);
        return;
      }

      // First delete account on server
      try {
        // Send request to delete account on server
        await axios.delete(`${CONFIG.BACKEND_URL}/api/users/${username}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        console.log("Account deleted on server");
      } catch (serverError) {
        console.error(
          "Failed to delete account on server:",
          serverError.message
        );
        Alert.alert(
          "Warning",
          "Could not delete account on server. Proceeding with local data deletion only."
        );
      }

      // Then delete all local data
      await deleteAllLocalData(username);

      Alert.alert(
        "Account Deleted",
        "Your account and all associated data have been permanently deleted.",
        [
          {
            text: "OK",
            onPress: () =>
              navigation.reset({
                index: 0,
                routes: [{ name: "Register" }],
              }),
          },
        ]
      );
    } catch (error) {
      console.error("Error deleting account:", error.message);
      Alert.alert("Error", "Failed to delete account. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const verifyPassword = async (inputPassword, storedHash) => {
    try {
      // Use whatever password verification method your app is using
      // This example assumes bcrypt or a similar hash is stored
      return inputPassword === storedHash; // Replace with actual verification
    } catch (error) {
      console.error("Error verifying password:", error);
      return false;
    }
  };

  const deleteAllLocalData = async (username) => {
    try {
      console.log("Deleting all local data for user:", username);

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
        "messageDestruction",
      ];

      // Delete fixed keys
      for (const key of fixedKeys) {
        await SecureStore.deleteItemAsync(key);
        console.log(`Deleted SecureStore key: ${key}`);
      }

      // Delete user-specific keys
      const userSpecificKeys = [
        `${username}_identityKeyPrivate`,
        `${username}_signingKeyPrivate`,
        `${username}_signedPreKeyPrivate`,
        `${username}_oneTimePreKeysPrivate`,
        `${username}_contacts`,
      ];

      for (const key of userSpecificKeys) {
        await SecureStore.deleteItemAsync(key);
        console.log(`Deleted user-specific key: ${key}`);
      }

      // Load contacts to delete their messages and ratchet states
      const contactsJson = await SecureStore.getItemAsync(
        `${username}_contacts`
      );
      let contactKeys = [];
      if (contactsJson) {
        try {
          const contacts = JSON.parse(contactsJson);
          if (Array.isArray(contacts)) {
            // Generate keys for all contacts
            contactKeys = contacts.flatMap((contactUsername) => [
              `messages_${username}_${contactUsername}`,
              `messages_${contactUsername}_${username}`,
              `ratchetState_${contactUsername}`,
              `ratchetState_${contactUsername}_updated`,
            ]);
          }
        } catch (parseError) {
          console.error("Failed to parse contacts:", parseError.message);
        }
      }

      // Delete contact-related keys
      for (const key of contactKeys) {
        await SecureStore.deleteItemAsync(key);
        console.log(`Deleted contact key: ${key}`);
      }

      console.log("All local data deleted successfully");
    } catch (error) {
      console.error("Error deleting local data:", error);
      throw error;
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={24} color="white" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Delete Account</Text>
      </View>
      <View style={styles.content}>
        <Text style={styles.description}>
          Are you sure you want to delete your account? This action is permanent
          and cannot be undone. All your messages, contacts, and other data will
          be permanently lost.
        </Text>

        <View style={styles.passwordContainer}>
          <Text style={styles.passwordLabel}>
            Enter your password to confirm:
          </Text>
          <View style={styles.inputContainer}>
            <TextInput
              style={styles.input}
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
          style={[
            styles.deleteButton,
            isLoading && styles.deleteButtonDisabled,
          ]}
          onPress={handleDelete}
          disabled={isLoading}
        >
          {isLoading ? (
            <ActivityIndicator size="small" color="#ffffff" />
          ) : (
            <Text style={styles.buttonText}>Delete Account</Text>
          )}
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.cancelButton}
          onPress={() => navigation.goBack()}
          disabled={isLoading}
        >
          <Text style={styles.cancelButtonText}>Cancel</Text>
        </TouchableOpacity>
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
    alignItems: "center",
  },
  description: {
    color: "white",
    fontSize: 16,
    textAlign: "center",
    marginBottom: 30,
  },
  passwordContainer: {
    width: "100%",
    marginBottom: 30,
  },
  passwordLabel: {
    color: "white",
    fontSize: 16,
    marginBottom: 10,
  },
  inputContainer: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#252525",
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#444",
  },
  input: {
    flex: 1,
    color: "white",
    paddingHorizontal: 15,
    paddingVertical: 12,
    fontSize: 16,
  },
  eyeButton: {
    padding: 10,
    marginRight: 5,
  },
  deleteButton: {
    backgroundColor: "#FF3B30",
    paddingVertical: 15,
    paddingHorizontal: 30,
    borderRadius: 10,
    alignItems: "center",
    marginBottom: 15,
    width: "100%",
  },
  deleteButtonDisabled: {
    backgroundColor: "#882220",
  },
  cancelButton: {
    backgroundColor: "#252525",
    paddingVertical: 15,
    paddingHorizontal: 30,
    borderRadius: 10,
    alignItems: "center",
    width: "100%",
  },
  buttonText: {
    color: "white",
    fontSize: 16,
    fontWeight: "600",
  },
  cancelButtonText: {
    color: "#FF3B30",
    fontSize: 16,
    fontWeight: "600",
  },
});

export default DeleteConfirmation;
