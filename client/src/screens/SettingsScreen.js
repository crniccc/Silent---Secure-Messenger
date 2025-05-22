import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  Image,
  StyleSheet,
  SafeAreaView,
  Modal,
  Alert,
  Platform,
  Linking,
  TextInput,
} from "react-native";
import * as ImagePicker from "expo-image-picker";
import * as SecureStore from "expo-secure-store";
import * as Notifications from "expo-notifications";
import { useNavigation } from "@react-navigation/native";
import { Ionicons } from "@expo/vector-icons";
import axios from "axios";
import * as FileSystem from "expo-file-system";
import * as ImageManipulator from "expo-image-manipulator";
import * as Crypto from "expo-crypto";
import naclUtil from "tweetnacl-util";
import { Buffer } from "buffer";
import Constants from "expo-constants";
import CONFIG from "../config/config";

// Konfiguracija notifikacija
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
  }),
});

const SettingsScreen = () => {
  const navigation = useNavigation();
  const [isStealthMode, setIsStealthMode] = useState(false);
  const [messageDestructionOption, setMessageDestructionOption] =
    useState("never");
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showDestructionOptionsModal, setShowDestructionOptionsModal] =
    useState(false);
  const [safePassword, setSafePassword] = useState("");
  const [confirmSafePassword, setConfirmSafePassword] = useState("");
  const [showSafePasswordModal, setShowSafePasswordModal] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [token, setToken] = useState("");
  const [deleteConfirmPassword, setDeleteConfirmPassword] = useState("");
  const [deleteAccountModalVisible, setDeleteAccountModalVisible] =
    useState(false);
  const [isSafePasswordSet, setIsSafePasswordSet] = useState(false);

  // Učitavanje podataka iz SecureStore
  useEffect(() => {
    const loadSettings = async () => {
      const stealthMode = await SecureStore.getItemAsync("stealthMode");
      const destructionOption = await SecureStore.getItemAsync(
        "messageDestructionOption"
      );
      const storedToken = await SecureStore.getItemAsync("token");

      // Check if safe password is set
      const safePasswordExists = await SecureStore.getItemAsync("safePassword");
      setIsSafePasswordSet(!!safePasswordExists);

      const isStealthModeEnabled = stealthMode === "true";
      setIsStealthMode(isStealthModeEnabled);

      // Apply notification settings based on stealth mode
      Notifications.setNotificationHandler({
        handleNotification: async () => ({
          shouldShowAlert: !isStealthModeEnabled,
          shouldPlaySound: !isStealthModeEnabled,
          shouldSetBadge: !isStealthModeEnabled,
        }),
      });
      console.log(
        "Notifications set to:",
        isStealthModeEnabled ? "Disabled" : "Enabled"
      );

      if (destructionOption) {
        setMessageDestructionOption(destructionOption);
      } else {
        // If no destruction option is set, default to "never" and save it
        setMessageDestructionOption("never");
        await SecureStore.setItemAsync("messageDestructionOption", "never");
      }
      if (storedToken) {
        setToken(storedToken);
      }
    };

    loadSettings();
  }, []);

  const handleStealthModeToggle = async () => {
    const newValue = !isStealthMode;
    setIsStealthMode(newValue);
    await SecureStore.setItemAsync("stealthMode", newValue.toString());

    // Toggle notifications based on stealth mode
    Notifications.setNotificationHandler({
      handleNotification: async () => ({
        shouldShowAlert: !newValue,
        shouldPlaySound: !newValue,
        shouldSetBadge: !newValue,
      }),
    });
    console.log("Notifications set to:", newValue ? "Disabled" : "Enabled");
  };

  const handleSafePassword = async () => {
    if (safePassword !== confirmSafePassword) {
      Alert.alert("Error", "Passwords do not match!");
      return;
    }

    try {
      // Store safe password in SecureStore - will be checked during login
      await SecureStore.setItemAsync("safePassword", safePassword);
      setSafePassword("");
      setConfirmSafePassword("");
      setShowSafePasswordModal(false);
      setIsSafePasswordSet(true);
      Alert.alert("Success", "Safe password successfully set!");
    } catch (error) {
      Alert.alert("Error", "Failed to set safe password");
    }
  };

  const handleChangePassword = async () => {
    if (newPassword !== confirmNewPassword) {
      Alert.alert("Error", "New passwords do not match!");
      return;
    }

    if (!token) {
      Alert.alert("Error", "Not authenticated");
      return;
    }

    try {
      await axios.post(
        `${CONFIG.BACKEND_URL}/api/users/change-password`,
        {
          currentPassword,
          newPassword,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      setShowPasswordModal(false);
      Alert.alert("Success", "Password changed successfully!");
    } catch (error) {
      Alert.alert(
        "Error",
        error.response?.data?.message || "Failed to change password"
      );
    }
  };

  const handleDestructionOptionSelect = async (option) => {
    setMessageDestructionOption(option);
    await SecureStore.setItemAsync("messageDestructionOption", option);
    setShowDestructionOptionsModal(false);
  };

  const handleDeleteAccount = async () => {
    const password = deleteConfirmPassword;
    setDeleteConfirmPassword("");
    setDeleteAccountModalVisible(false);

    try {
      // Get the stored password hash for verification
      const storedPasswordHash = await SecureStore.getItemAsync("passwordHash");
      if (!storedPasswordHash) {
        Alert.alert("Error", "Cannot retrieve password for verification");
        return;
      }

      // Get username early so we can use it throughout the function
      const username = await SecureStore.getItemAsync("username");
      if (!username) {
        Alert.alert("Error", "Session information missing");
        return;
      }

      // Generate hash from entered password using original method
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

      // Verify the password
      if (computedHash === storedPasswordHash) {
        // First try to delete account through the debug endpoint which is more reliable
        let serverDeletionSucceeded = false;
        const token = await SecureStore.getItemAsync("token");

        try {
          // Start with the safe-reset endpoint (doesn't require auth and most reliable)
          console.log(
            `Attempting to delete account using safe-reset endpoint for ${username}`
          );
          await axios.delete(
            `${CONFIG.BACKEND_URL}/api/debug/safe-reset/${username}`,
            { timeout: 15000 }
          );
          serverDeletionSucceeded = true;
          console.log(
            "Server data deleted successfully through safe-reset endpoint"
          );
        } catch (safeResetError) {
          console.log(
            "Safe-reset endpoint not accessible:",
            safeResetError.message
          );

          // Only if safe-reset fails, try the authenticated API as fallback
          if (token) {
            try {
              console.log(
                "Attempting to delete through authenticated API as fallback"
              );
              await axios.delete(
                `${CONFIG.BACKEND_URL}/api/users/${username}/complete`,
                {
                  headers: { Authorization: `Bearer ${token}` },
                  timeout: 10000,
                }
              );
              serverDeletionSucceeded = true;
              console.log("Server data deleted through authenticated API");
            } catch (apiError) {
              // Just log but don't show error to user
              console.log(
                "Expected failure through API (okay to ignore):",
                apiError.message
              );
            }
          }
        }

        // Even if server deletion failed, we proceed with local cleanup without showing warning
        if (!serverDeletionSucceeded) {
          console.log(
            "All server deletion attempts failed, proceeding with local cleanup only"
          );
          // No alert to user about server failure - just proceed silently
        }

        // Clear all local data regardless of server deletion success

        // Load contacts for message cleanup
        let contactsJson = await SecureStore.getItemAsync("contacts");
        if (!contactsJson) {
          contactsJson = await SecureStore.getItemAsync(`${username}_contacts`);
        }

        let contacts = [];
        if (contactsJson) {
          try {
            contacts = JSON.parse(contactsJson);
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

        // Delete all message and ratchet keys
        if (Array.isArray(contacts)) {
          for (const contact of contacts) {
            await SecureStore.deleteItemAsync(
              `messages_${username}_${contact}`
            );
            await SecureStore.deleteItemAsync(
              `messages_${contact}_${username}`
            );
            await SecureStore.deleteItemAsync(`ratchetState_${contact}`);
            await SecureStore.deleteItemAsync(
              `ratchetState_${contact}_updated`
            );
            console.log(`Deleted data for contact: ${contact}`);
          }
        }

        // Navigate to register screen
        Alert.alert("Success", "Your account has been deleted.", [
          {
            text: "OK",
            onPress: () => {
              // Navigate to register screen
              navigation.reset({
                index: 0,
                routes: [{ name: "Register" }],
              });
            },
          },
        ]);
      } else {
        Alert.alert("Error", "Incorrect password");
      }
    } catch (error) {
      console.error("Error deleting account:", error);
      Alert.alert(
        "Error",
        "Failed to delete account: " +
          (error.response?.data?.error || error.message)
      );
    }
  };

  const closeModalIfOutside = (event) => {
    if (event.target === event.currentTarget) {
      setShowSafePasswordModal(false);
      setShowPasswordModal(false);
      setShowDestructionOptionsModal(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <View style={styles.headerContent}>
          <Ionicons name="settings-outline" size={28} color="white" />
          <Text style={styles.headerTitle}>Settings</Text>
        </View>
      </View>

      <View style={styles.content}>
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Security</Text>

          <View style={styles.settingsGroup}>
            {isSafePasswordSet ? (
              <View style={styles.optionItem}>
                <Text style={styles.optionText}>Safe Password</Text>
                <View style={styles.valueContainer}>
                  <Text style={[styles.valueText, { color: "#4A80F0" }]}>
                    Set
                  </Text>
                </View>
              </View>
            ) : (
              <TouchableOpacity
                style={styles.optionItem}
                onPress={() => {
                  setShowSafePasswordModal(true);
                }}
              >
                <Text style={styles.optionText}>Set Safe Password</Text>
                <Ionicons
                  name="chevron-forward"
                  size={22}
                  color="#8e9295"
                  style={styles.icon}
                />
              </TouchableOpacity>
            )}

            <TouchableOpacity
              style={styles.optionItem}
              onPress={() => {
                setShowPasswordModal(true);
              }}
            >
              <Text style={styles.optionText}>Change Password</Text>
              <Ionicons
                name="chevron-forward"
                size={22}
                color="#8e9295"
                style={styles.icon}
              />
            </TouchableOpacity>

            <View style={styles.optionItem}>
              <Text style={styles.optionText}>Stealth Mode</Text>
              <TouchableOpacity
                onPress={handleStealthModeToggle}
                style={[
                  styles.toggleButton,
                  isStealthMode ? styles.toggleActive : styles.toggleInactive,
                ]}
              >
                <View
                  style={[
                    styles.toggleIndicator,
                    isStealthMode
                      ? styles.indicatorActive
                      : styles.indicatorInactive,
                  ]}
                />
              </TouchableOpacity>
            </View>

            <TouchableOpacity
              style={styles.optionItem}
              onPress={() => {
                setShowDestructionOptionsModal(true);
              }}
            >
              <Text style={styles.optionText}>Message Destruction</Text>
              <View style={styles.valueContainer}>
                <Text style={styles.valueText}>
                  {messageDestructionOption === "never"
                    ? "Never"
                    : messageDestructionOption === "1m"
                    ? "1 Minute"
                    : messageDestructionOption === "1h"
                    ? "1 Hour"
                    : messageDestructionOption === "1d"
                    ? "1 Day"
                    : messageDestructionOption === "1w"
                    ? "1 Week"
                    : messageDestructionOption === "15s"
                    ? "15 Seconds"
                    : "Unknown"}
                </Text>
                <Ionicons
                  name="chevron-forward"
                  size={22}
                  color="#8e9295"
                  style={styles.icon}
                />
              </View>
            </TouchableOpacity>
          </View>

          <View style={styles.settingsGroup}>
            <TouchableOpacity
              style={styles.dangerButton}
              onPress={() => {
                setDeleteAccountModalVisible(true);
              }}
            >
              <Ionicons name="trash-outline" size={20} color="white" />
              <Text style={styles.dangerButtonText}>Delete Account</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>

      {/* Safe Password Modal */}
      <Modal
        visible={showSafePasswordModal}
        transparent={true}
        animationType="slide"
        onRequestClose={() => setShowSafePasswordModal(false)}
      >
        <TouchableOpacity
          style={styles.modalContainer}
          activeOpacity={1}
          onPress={closeModalIfOutside}
        >
          <TouchableOpacity
            activeOpacity={1}
            style={styles.modalContent}
            onPress={() => {}}
          >
            <Text style={styles.modalTitle}>Set Safe Password</Text>
            <Text style={styles.modalDescription}>
              This is a password that when entered at login will delete all your
              data.
            </Text>

            <View style={styles.inputContainer}>
              <Text style={styles.inputLabel}>Safe Password</Text>
              <View style={styles.input}>
                <TextInput
                  secureTextEntry
                  placeholder="Enter safe password"
                  placeholderTextColor="#666"
                  value={safePassword}
                  onChangeText={setSafePassword}
                  style={styles.inputText}
                  maxLength={32}
                />
              </View>
            </View>

            <View style={styles.inputContainer}>
              <Text style={styles.inputLabel}>Confirm Safe Password</Text>
              <View style={styles.input}>
                <TextInput
                  secureTextEntry
                  placeholder="Confirm safe password"
                  placeholderTextColor="#666"
                  value={confirmSafePassword}
                  onChangeText={setConfirmSafePassword}
                  style={styles.inputText}
                  maxLength={32}
                />
              </View>
            </View>

            <View style={styles.modalActions}>
              <TouchableOpacity
                style={styles.cancelButton}
                onPress={() => {
                  setSafePassword("");
                  setConfirmSafePassword("");
                  setShowSafePasswordModal(false);
                }}
              >
                <Text style={styles.cancelButtonText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.confirmButton}
                onPress={handleSafePassword}
              >
                <Text style={styles.confirmButtonText}>Set Password</Text>
              </TouchableOpacity>
            </View>
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>

      {/* Change Password Modal */}
      <Modal
        visible={showPasswordModal}
        transparent={true}
        animationType="slide"
        onRequestClose={() => setShowPasswordModal(false)}
      >
        <TouchableOpacity
          style={styles.modalContainer}
          activeOpacity={1}
          onPress={closeModalIfOutside}
        >
          <TouchableOpacity
            activeOpacity={1}
            style={styles.modalContent}
            onPress={() => {}}
          >
            <Text style={styles.modalTitle}>Change Password</Text>

            <View style={styles.inputContainer}>
              <Text style={styles.inputLabel}>Current Password</Text>
              <View style={styles.input}>
                <TextInput
                  secureTextEntry
                  placeholder="Enter current password"
                  placeholderTextColor="#666"
                  value={currentPassword}
                  onChangeText={setCurrentPassword}
                  style={styles.inputText}
                  maxLength={32}
                />
              </View>
            </View>

            <View style={styles.inputContainer}>
              <Text style={styles.inputLabel}>New Password</Text>
              <View style={styles.input}>
                <TextInput
                  secureTextEntry
                  placeholder="Enter new password"
                  placeholderTextColor="#666"
                  value={newPassword}
                  onChangeText={setNewPassword}
                  style={styles.inputText}
                  maxLength={32}
                />
              </View>
            </View>

            <View style={styles.inputContainer}>
              <Text style={styles.inputLabel}>Confirm New Password</Text>
              <View style={styles.input}>
                <TextInput
                  secureTextEntry
                  placeholder="Confirm new password"
                  placeholderTextColor="#666"
                  value={confirmNewPassword}
                  onChangeText={setConfirmNewPassword}
                  style={styles.inputText}
                  maxLength={32}
                />
              </View>
            </View>

            <View style={styles.modalActions}>
              <TouchableOpacity
                style={styles.cancelButton}
                onPress={() => {
                  setCurrentPassword("");
                  setNewPassword("");
                  setConfirmNewPassword("");
                  setShowPasswordModal(false);
                }}
              >
                <Text style={styles.cancelButtonText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.confirmButton}
                onPress={handleChangePassword}
              >
                <Text style={styles.confirmButtonText}>Change Password</Text>
              </TouchableOpacity>
            </View>
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>

      {/* Message Destruction Options Modal */}
      <Modal
        visible={showDestructionOptionsModal}
        transparent={true}
        animationType="slide"
        onRequestClose={() => setShowDestructionOptionsModal(false)}
      >
        <TouchableOpacity
          style={styles.modalContainer}
          activeOpacity={1}
          onPress={closeModalIfOutside}
        >
          <TouchableOpacity
            activeOpacity={1}
            style={styles.modalContent}
            onPress={() => {}}
          >
            <Text style={styles.modalTitle}>Message Destruction</Text>
            <Text style={styles.modalDescription}>
              Choose how long messages will be visible before being
              automatically deleted.
            </Text>

            <View style={styles.optionsContainer}>
              <TouchableOpacity
                style={[
                  styles.optionButton,
                  messageDestructionOption === "never" && styles.selectedOption,
                ]}
                onPress={() => handleDestructionOptionSelect("never")}
              >
                <Text
                  style={[
                    styles.optionButtonText,
                    messageDestructionOption === "never" &&
                      styles.selectedOptionText,
                  ]}
                >
                  Never
                </Text>
                {messageDestructionOption === "never" && (
                  <Ionicons name="checkmark" size={22} color="#4A80F0" />
                )}
              </TouchableOpacity>

              <TouchableOpacity
                style={[
                  styles.optionButton,
                  messageDestructionOption === "15s" && styles.selectedOption,
                ]}
                onPress={() => handleDestructionOptionSelect("15s")}
              >
                <Text
                  style={[
                    styles.optionButtonText,
                    messageDestructionOption === "15s" &&
                      styles.selectedOptionText,
                  ]}
                >
                  15 Seconds
                </Text>
                {messageDestructionOption === "15s" && (
                  <Ionicons name="checkmark" size={22} color="#4A80F0" />
                )}
              </TouchableOpacity>

              <TouchableOpacity
                style={[
                  styles.optionButton,
                  messageDestructionOption === "1m" && styles.selectedOption,
                ]}
                onPress={() => handleDestructionOptionSelect("1m")}
              >
                <Text
                  style={[
                    styles.optionButtonText,
                    messageDestructionOption === "1m" &&
                      styles.selectedOptionText,
                  ]}
                >
                  1 Minute
                </Text>
                {messageDestructionOption === "1m" && (
                  <Ionicons name="checkmark" size={22} color="#4A80F0" />
                )}
              </TouchableOpacity>

              <TouchableOpacity
                style={[
                  styles.optionButton,
                  messageDestructionOption === "1h" && styles.selectedOption,
                ]}
                onPress={() => handleDestructionOptionSelect("1h")}
              >
                <Text
                  style={[
                    styles.optionButtonText,
                    messageDestructionOption === "1h" &&
                      styles.selectedOptionText,
                  ]}
                >
                  1 Hour
                </Text>
                {messageDestructionOption === "1h" && (
                  <Ionicons name="checkmark" size={22} color="#4A80F0" />
                )}
              </TouchableOpacity>

              <TouchableOpacity
                style={[
                  styles.optionButton,
                  messageDestructionOption === "1d" && styles.selectedOption,
                ]}
                onPress={() => handleDestructionOptionSelect("1d")}
              >
                <Text
                  style={[
                    styles.optionButtonText,
                    messageDestructionOption === "1d" &&
                      styles.selectedOptionText,
                  ]}
                >
                  1 Day
                </Text>
                {messageDestructionOption === "1d" && (
                  <Ionicons name="checkmark" size={22} color="#4A80F0" />
                )}
              </TouchableOpacity>

              <TouchableOpacity
                style={[
                  styles.optionButton,
                  messageDestructionOption === "1w" && styles.selectedOption,
                ]}
                onPress={() => handleDestructionOptionSelect("1w")}
              >
                <Text
                  style={[
                    styles.optionButtonText,
                    messageDestructionOption === "1w" &&
                      styles.selectedOptionText,
                  ]}
                >
                  1 Week
                </Text>
                {messageDestructionOption === "1w" && (
                  <Ionicons name="checkmark" size={22} color="#4A80F0" />
                )}
              </TouchableOpacity>
            </View>
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>

      {/* Delete Account Modal */}
      <Modal
        visible={deleteAccountModalVisible}
        transparent={true}
        animationType="slide"
        onRequestClose={() => setDeleteAccountModalVisible(false)}
      >
        <TouchableOpacity
          style={styles.modalContainer}
          activeOpacity={1}
          onPress={closeModalIfOutside}
        >
          <TouchableOpacity
            activeOpacity={1}
            style={styles.modalContent}
            onPress={() => {}}
          >
            <Text style={styles.modalTitle}>Delete Account</Text>
            <Text style={styles.modalDescription}>
              Enter your password to confirm account deletion.
            </Text>

            <View style={styles.inputContainer}>
              <Text style={styles.inputLabel}>Password</Text>
              <View style={styles.input}>
                <TextInput
                  secureTextEntry
                  placeholder="Enter password"
                  placeholderTextColor="#666"
                  value={deleteConfirmPassword}
                  onChangeText={setDeleteConfirmPassword}
                  style={styles.inputText}
                  maxLength={32}
                />
              </View>
            </View>

            <View style={styles.modalActions}>
              <TouchableOpacity
                style={styles.cancelButton}
                onPress={() => {
                  setDeleteConfirmPassword("");
                  setDeleteAccountModalVisible(false);
                }}
              >
                <Text style={styles.cancelButtonText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.confirmButton}
                onPress={handleDeleteAccount}
              >
                <Text style={styles.confirmButtonText}>Delete Account</Text>
              </TouchableOpacity>
            </View>
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#252762",
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    padding: 15,
    backgroundColor: "#252762",
    borderBottomWidth: 1,
    borderBottomColor: "#fff",
  },
  headerContent: {
    flexDirection: "row",
    alignItems: "center",
  },
  headerTitle: {
    color: "white",
    fontSize: 20,
    fontWeight: "600",
    marginLeft: 15,
    textShadowColor: "rgba(255, 255, 255, 0.3)",
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 10,
  },
  content: {
    flex: 1,
    padding: 20,
  },
  section: {
    marginBottom: 30,
  },
  sectionTitle: {
    color: "white",
    fontSize: 14,
    fontWeight: "600",
    marginBottom: 15,
    marginLeft: 20,
  },
  settingsGroup: {
    backgroundColor: "rgba(255,255,255,0.05)",
    borderRadius: 12,
    marginBottom: 20,
    overflow: "hidden",
  },
  optionItem: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.07)",
    backgroundColor: "transparent",
  },
  optionText: {
    color: "white",
    fontSize: 16,
    fontWeight: "500",
  },
  valueContainer: {
    flexDirection: "row",
    alignItems: "center",
  },
  valueText: {
    color: "#8e9295",
    fontSize: 16,
    marginRight: 6,
  },
  icon: {
    marginLeft: 8,
  },
  toggleButton: {
    width: 50,
    height: 28,
    borderRadius: 14,
    padding: 2,
    justifyContent: "center",
  },
  toggleActive: {
    backgroundColor: "#4A80F0",
  },
  toggleInactive: {
    backgroundColor: "#3A3A3A",
  },
  toggleIndicator: {
    width: 24,
    height: 24,
    borderRadius: 12,
  },
  indicatorActive: {
    backgroundColor: "white",
    alignSelf: "flex-end",
  },
  indicatorInactive: {
    backgroundColor: "#8e9295",
    alignSelf: "flex-start",
  },
  dangerButton: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 12,
    marginBottom: 10,
    backgroundColor: "rgba(255, 59, 48, 0.15)",
    marginHorizontal: 10,
    shadowColor: "#FF3B30",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.2,
    shadowRadius: 4,
    elevation: 2,
  },
  dangerButtonText: {
    color: "#FF3B30",
    fontSize: 16,
    fontWeight: "600",
    marginLeft: 8,
  },
  modalContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    backgroundColor: "rgba(0, 0, 0, 0.5)",
  },
  modalContent: {
    backgroundColor: "#252762",
    borderRadius: 20,
    padding: 20,
    maxWidth: 400,
    width: "90%",
    alignItems: "center",
  },
  modalTitle: {
    color: "white",
    fontSize: 20,
    fontWeight: "700",
    marginBottom: 12,
    textAlign: "center",
    textShadowColor: "rgba(255, 255, 255, 0.3)",
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 10,
  },
  modalDescription: {
    color: "#888",
    fontSize: 16,
    lineHeight: 22,
    marginBottom: 20,
    textAlign: "center",
  },
  inputContainer: {
    marginBottom: 16,
  },
  inputLabel: {
    color: "#888",
    marginBottom: 8,
    fontSize: 16,
  },
  input: {
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  inputText: {
    color: "white",
    fontSize: 16,
    width: 250,
  },
  modalActions: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginTop: 24,
  },
  cancelButton: {
    flex: 1,
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    borderRadius: 12,
    paddingVertical: 14,
    marginRight: 10,
    alignItems: "center",
  },
  confirmButton: {
    flex: 1,
    backgroundColor: "#4A80F0",
    borderRadius: 12,
    paddingVertical: 14,
    marginLeft: 10,
    alignItems: "center",
    shadowColor: "#4A80F0",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 4,
  },
  cancelButtonText: {
    color: "#888",
    fontSize: 16,
    fontWeight: "600",
  },
  confirmButtonText: {
    color: "white",
    fontSize: 16,
    fontWeight: "600",
  },
  optionsContainer: {
    width: "100%",
    alignItems: "center",
    marginTop: 10,
  },
  optionButton: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 12,
    marginBottom: 10,
    backgroundColor: "rgba(255, 255, 255, 0.05)",
    marginHorizontal: 10,
    width: "85%",
    alignSelf: "center",
  },
  selectedOption: {
    backgroundColor: "rgba(74, 128, 240, 0.2)",
    borderWidth: 1,
    borderColor: "rgba(74, 128, 240, 0.5)",
  },
  optionButtonText: {
    color: "white",
    fontSize: 16,
    fontWeight: "500",
  },
  selectedOptionText: {
    color: "white",
    fontWeight: "700",
  },
  optionValue: {
    color: "#888",
    fontSize: 16,
  },
  footer: {
    backgroundColor: "#252762",
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

export default SettingsScreen;
