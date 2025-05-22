import React, { useState } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  Alert,
  ActivityIndicator,
} from "react-native";
import { useNavigation, useRoute } from "@react-navigation/native";
import { Ionicons } from "@expo/vector-icons";
import axios from "axios";
import * as SecureStore from "expo-secure-store";
import CONFIG from "../config/config";
import bcrypt from "react-native-bcrypt";

const ChangePassword = () => {
  const navigation = useNavigation();
  const route = useRoute();
  const { token, userId } = route.params || {};
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const handleChangePassword = async () => {
    setIsLoading(true);
    try {
      if (!currentPassword || !newPassword || !confirmPassword) {
        Alert.alert("Error", "Please fill all fields");
        return;
      }
      if (newPassword !== confirmPassword) {
        Alert.alert("Error", "New passwords do not match");
        return;
      }
      if (newPassword.length < 4) {
        Alert.alert("Error", "New password must be at least 4 characters");
        return;
      }

      const storedToken = token || (await SecureStore.getItemAsync("token"));
      const storedPasswordHash = await SecureStore.getItemAsync("passwordHash");

      // Provjeri trenutnu lozinku
      const isCurrentValid = bcrypt.compareSync(
        currentPassword,
        storedPasswordHash
      );
      if (!isCurrentValid) {
        Alert.alert("Error", "Current password is incorrect");
        return;
      }

      // Generiraj novi hash
      const salt = bcrypt.genSaltSync(10);
      const newPasswordHash = bcrypt.hashSync(newPassword, salt);

      // Ažuriraj na serveru
      await axios.patch(
        `${CONFIG.BACKEND_URL}/api/users/${userId}`,
        { passwordHash: newPasswordHash },
        { headers: { Authorization: `Bearer ${storedToken}` } }
      );

      // Ažuriraj SecureStore
      await SecureStore.setItemAsync("passwordHash", newPasswordHash);

      Alert.alert("Success", "Password changed successfully");
      navigation.goBack();
    } catch (error) {
      console.error("Change password error:", error.message);
      Alert.alert("Error", "Failed to change password");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={24} color="white" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Change Password</Text>
      </View>
      <View style={styles.content}>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>Current Password:</Text>
          <View style={styles.passwordContainer}>
            <TextInput
              style={styles.input}
              placeholder="Enter current password"
              placeholderTextColor="#888"
              secureTextEntry={!showCurrentPassword}
              value={currentPassword}
              onChangeText={setCurrentPassword}
            />
            <TouchableOpacity
              style={styles.eyeButton}
              onPress={() => setShowCurrentPassword(!showCurrentPassword)}
            >
              <Ionicons
                name={showCurrentPassword ? "eye-off" : "eye"}
                size={24}
                color="#888"
              />
            </TouchableOpacity>
          </View>
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>New Password:</Text>
          <View style={styles.passwordContainer}>
            <TextInput
              style={styles.input}
              placeholder="Enter new password"
              placeholderTextColor="#888"
              secureTextEntry={!showNewPassword}
              value={newPassword}
              onChangeText={setNewPassword}
            />
            <TouchableOpacity
              style={styles.eyeButton}
              onPress={() => setShowNewPassword(!showNewPassword)}
            >
              <Ionicons
                name={showNewPassword ? "eye-off" : "eye"}
                size={24}
                color="#888"
              />
            </TouchableOpacity>
          </View>
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>Confirm New Password:</Text>
          <View style={styles.passwordContainer}>
            <TextInput
              style={styles.input}
              placeholder="Confirm new password"
              placeholderTextColor="#888"
              secureTextEntry={!showConfirmPassword}
              value={confirmPassword}
              onChangeText={setConfirmPassword}
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
          onPress={handleChangePassword}
          disabled={isLoading}
        >
          {isLoading ? (
            <ActivityIndicator size="small" color="#ffffff" />
          ) : (
            <Text style={styles.buttonText}>Change Password</Text>
          )}
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
});

export default ChangePassword;
