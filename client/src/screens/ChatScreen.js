import "react-native-get-random-values";
import React, { useState, useEffect, useRef } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  FlatList,
  StyleSheet,
  SafeAreaView,
  StatusBar,
  Alert,
  KeyboardAvoidingView,
  Platform,
  Image,
  ActivityIndicator,
  Linking,
  Dimensions,
  useWindowDimensions,
} from "react-native";
import * as SecureStore from "expo-secure-store";
import io from "socket.io-client";
import axios from "axios";
import { Ionicons } from "@expo/vector-icons";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import { v4 as uuidv4 } from "uuid";
import * as ImagePicker from "expo-image-picker";
import * as FileSystem from "expo-file-system";
import * as ImageManipulator from "expo-image-manipulator";
import Modal from "react-native-modal";
import ImageViewer from "react-native-image-zoom-viewer";
import enhancedRandom from "../utils/EnhancedRandom";
import * as Permissions from "expo-permissions";
import CONFIG from "../config/config";

// DoubleRatchet class with enhanced security
class DoubleRatchet {
  constructor(sharedSecret, chainKey, isInitiator = false, dhKeyPair = null) {
    this.rootKey = sharedSecret;
    this.chainKey = chainKey;
    this.isInitiator = isInitiator;
    this.dhKeyPair = dhKeyPair; // Will be initialized with enhanced randomness later
    this.remotePublicKey = null;
    this.sendingChainKey = null;
    this.receivingChainKey = null;
    this.sendingMessageNumber = 0;
    this.receivingMessageNumber = 0;
    this.skippedMessageKeys = new Map();
    this.MAX_SKIP = 100;
    this.MAX_MESSAGES_BEFORE_DH_RESET = 5; // Reset DH ratchet after 5 messages
    this.messagesSinceLastReset = 0; // Counter for messages since last DH ratchet
    this.debug = true;
    this.useEnhancedRandom = true; // Flag to enable enhanced randomness
  }

  // Enhanced initialization with stronger randomness
  async initWithEnhancedRandomness() {
    if (!this.dhKeyPair && this.useEnhancedRandom) {
      try {
        // Use enhanced randomness for the DH key pair
        this.dhKeyPair = await enhancedRandom.boxKeyPair();
        this.log("DH Key Pair generated with enhanced randomness");
      } catch (error) {
        this.error(
          "Enhanced randomness failed, falling back to standard randomness:",
          error
        );
        // Fallback to standard randomness
        this.dhKeyPair = nacl.box.keyPair();
      }
    } else if (!this.dhKeyPair) {
      // Standard initialization
      this.dhKeyPair = nacl.box.keyPair();
    }
    return this;
  }

  setDebug(enabled) {
    this.debug = enabled;
    return this;
  }

  log(...args) {
    if (this.debug) {
      console.log("(NOBRIDGE) LOG", ...args);
    }
  }

  error(...args) {
    if (this.debug) {
      console.error("(NOBRIDGE) ERROR", ...args);
    }
  }

  deriveKey(key, info, outputLength = 32) {
    let result = new Uint8Array();
    let currentInput = new Uint8Array([...key, ...naclUtil.decodeUTF8(info)]);
    let bytesGenerated = 0;

    while (bytesGenerated < outputLength) {
      const hash = nacl.hash(currentInput);
      result = new Uint8Array([...result, ...hash]);
      bytesGenerated += hash.length;

      const counter = new Uint8Array([(bytesGenerated / 64) & 0xff]);
      currentInput = new Uint8Array([...hash, ...counter]);
    }

    return result.slice(0, outputLength);
  }

  deriveRootKeyAndChainKeys(dhOutput) {
    const derivedSecret = this.deriveKey(
      new Uint8Array([...this.rootKey, ...dhOutput]),
      "ratchet-kdf",
      96
    );

    const rootKey = derivedSecret.slice(0, 32);
    const sendingChainKey = derivedSecret.slice(32, 64);
    const receivingChainKey = derivedSecret.slice(64, 96);

    if (!sendingChainKey || sendingChainKey.length !== 32) {
      this.error(
        "Invalid sendingChainKey derived:",
        Array.from(sendingChainKey)
      );
      throw new Error("Failed to derive valid sendingChainKey");
    }
    if (!receivingChainKey || receivingChainKey.length !== 32) {
      this.error(
        "Invalid receivingChainKey derived:",
        Array.from(receivingChainKey)
      );
      throw new Error("Failed to derive valid receivingChainKey");
    }

    return { rootKey, sendingChainKey, receivingChainKey };
  }

  initializeSession(remotePublicKey) {
    this.log("Initializing session with remote key:", remotePublicKey);
    this.log(
      "Root key on initialization:",
      naclUtil.encodeBase64(this.rootKey)
    );
    this.log(
      "Chain key on initialization:",
      naclUtil.encodeBase64(this.chainKey)
    );
    this.log("Is initiator:", this.isInitiator);
    this.log(
      "Local DH public key:",
      naclUtil.encodeBase64(this.dhKeyPair.publicKey)
    );
    this.log(
      "Local DH private key:",
      naclUtil.encodeBase64(this.dhKeyPair.secretKey)
    );

    this.remotePublicKey = naclUtil.decodeBase64(remotePublicKey);

    if (this.isInitiator) {
      this.sendingChainKey = this.chainKey;
      this.receivingChainKey = this.chainKey;
    } else {
      this.receivingChainKey = this.chainKey;
      this.sendingChainKey = this.chainKey;
    }

    if (!this.sendingChainKey || !this.receivingChainKey) {
      throw new Error(
        "Failed to initialize chain keys: keys are null or empty"
      );
    }

    this.sendingMessageNumber = 0;
    this.receivingMessageNumber = 0;

    this.log("Initial chain keys set:", {
      sendingChainKey: naclUtil.encodeBase64(this.sendingChainKey),
      receivingChainKey: naclUtil.encodeBase64(this.receivingChainKey),
    });
  }

  dhRatchetStep() {
    this.log("Performing DH ratchet step");
    this.log(
      "Current root key before DH ratchet:",
      naclUtil.encodeBase64(this.rootKey)
    );
    const dhOutput = nacl.box.before(
      this.remotePublicKey,
      this.dhKeyPair.secretKey
    );
    this.log("DH output:", naclUtil.encodeBase64(dhOutput));
    const derivedKeys = this.deriveRootKeyAndChainKeys(dhOutput);
    this.rootKey = derivedKeys.rootKey;

    if (this.isInitiator) {
      this.sendingChainKey = derivedKeys.sendingChainKey;
      this.receivingChainKey = derivedKeys.receivingChainKey;
    } else {
      this.receivingChainKey = derivedKeys.sendingChainKey;
      this.sendingChainKey = derivedKeys.receivingChainKey;
    }

    if (!this.sendingChainKey || !this.receivingChainKey) {
      throw new Error("DH ratchet failed: chain keys are null or empty");
    }

    this.sendingMessageNumber = 0;
    this.receivingMessageNumber = 0;

    this.log("DH ratchet completed, new keys:", {
      rootKey: naclUtil.encodeBase64(this.rootKey),
      sendingChainKey: naclUtil.encodeBase64(this.sendingChainKey),
      receivingChainKey: naclUtil.encodeBase64(this.receivingChainKey),
    });
  }

  deriveMessageKey(chainKey) {
    if (!chainKey) {
      this.error("Chain key is null or undefined during deriveMessageKey");
      throw new Error("Chain key is null or undefined");
    }

    const derivedKeys = this.deriveKey(chainKey, "message-kdf", 64);
    const newChainKey = derivedKeys.slice(0, 32);
    const messageKey = derivedKeys.slice(32, 64);

    if (!newChainKey || !messageKey) {
      this.error("Failed to derive message key:", { newChainKey, messageKey });
      throw new Error("Failed to derive valid message key");
    }

    return { chainKey: newChainKey, messageKey };
  }

  // Enhanced encrypt method that uses stronger randomness for nonce when available
  async encrypt(plaintext) {
    this.log(`Encrypting message`);
    this.log(
      "Root key during encryption:",
      naclUtil.encodeBase64(this.rootKey)
    );
    this.log(
      "Sending chain key before encryption:",
      naclUtil.encodeBase64(this.sendingChainKey)
    );
    this.log("Sending message number:", this.sendingMessageNumber);
    this.log("Messages since last DH reset:", this.messagesSinceLastReset);

    // Check if we need to perform a DH ratchet reset after MAX_MESSAGES_BEFORE_DH_RESET messages
    if (this.messagesSinceLastReset >= this.MAX_MESSAGES_BEFORE_DH_RESET) {
      this.log(
        `Resetting DH ratchet after ${this.MAX_MESSAGES_BEFORE_DH_RESET} messages`
      );

      // Create a new DH key pair with enhanced randomness
      if (this.useEnhancedRandom) {
        try {
          this.dhKeyPair = await enhancedRandom.boxKeyPair();
          this.log(
            "New DH Key Pair generated with enhanced randomness for ratchet reset"
          );
        } catch (error) {
          this.error(
            "Enhanced randomness failed, falling back to standard randomness:",
            error
          );
          // Fallback to standard randomness
          this.dhKeyPair = nacl.box.keyPair();
        }
      } else {
        // Standard key generation
        this.dhKeyPair = nacl.box.keyPair();
      }

      // Perform DH ratchet step
      this.dhRatchetStep();

      // Reset message counter
      this.messagesSinceLastReset = 0;
    }

    if (!this.sendingChainKey) {
      this.error("sendingChainKey is null before encryption");
      throw new Error("sendingChainKey is null before encryption");
    }

    const derived = this.deriveMessageKey(this.sendingChainKey);
    this.sendingChainKey = derived.chainKey;
    const messageKey = derived.messageKey;

    this.log("Message encryption key:", naclUtil.encodeBase64(messageKey));
    this.log(
      "Sending chain key after derivation:",
      naclUtil.encodeBase64(this.sendingChainKey)
    );

    // Use enhanced randomness for the nonce when available
    let nonce;
    if (this.useEnhancedRandom) {
      try {
        nonce = await enhancedRandom.getRandomBytes(nacl.secretbox.nonceLength);
      } catch (error) {
        this.error(
          "Enhanced randomness failed for nonce, using standard randomness:",
          error
        );
        nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      }
    } else {
      nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    }

    const ciphertext = nacl.secretbox(
      naclUtil.decodeUTF8(plaintext),
      nonce,
      messageKey
    );

    if (!ciphertext) {
      this.error("Encryption failed: Invalid plaintext or key");
      throw new Error("Encryption failed: Invalid plaintext or key");
    }

    const header = {
      dhPubKey: naclUtil.encodeBase64(this.dhKeyPair.publicKey),
      messageIndex: this.sendingMessageNumber,
      prevChainLength: 0,
    };

    this.sendingMessageNumber++;
    this.messagesSinceLastReset++; // Increment the counter for messages since last DH reset

    return {
      header: header,
      ciphertext: naclUtil.encodeBase64(ciphertext),
      nonce: naclUtil.encodeBase64(nonce),
    };
  }

  decrypt(encryptedMessage) {
    const header = encryptedMessage.header;
    const ciphertextStr = encryptedMessage.ciphertext;
    const nonceStr = encryptedMessage.nonce;

    this.log("Decrypting message with header:", header);
    this.log(
      "Root key during decryption:",
      naclUtil.encodeBase64(this.rootKey)
    );
    this.log(
      "Receiving chain key before decryption:",
      naclUtil.encodeBase64(this.receivingChainKey)
    );
    this.log("Receiving message number:", this.receivingMessageNumber);

    if (!header.dhPubKey) {
      this.error("Missing dhPubKey in message header");
      throw new Error("Missing dhPubKey in message header");
    }

    const isValidBase64 = (str) => {
      try {
        if (typeof str !== "string") return false;
        const base64Regex = /^[A-Za-z0-9+/=]+$/;
        return base64Regex.test(str) && str.length % 4 === 0;
      } catch {
        return false;
      }
    };

    if (!isValidBase64(ciphertextStr)) {
      this.error(`Invalid base64 encoding for ciphertext: ${ciphertextStr}`);
      throw new Error(
        `Invalid base64 encoding for ciphertext: ${ciphertextStr}`
      );
    }
    if (!isValidBase64(nonceStr)) {
      this.error(`Invalid base64 encoding for nonce: ${nonceStr}`);
      throw new Error(`Invalid base64 encoding for nonce: ${nonceStr}`);
    }

    const ciphertext = naclUtil.decodeBase64(ciphertextStr);
    const nonce = naclUtil.decodeBase64(nonceStr);
    const remotePublicKey = naclUtil.decodeBase64(header.dhPubKey);

    const remotePublicKeyStr = naclUtil.encodeBase64(remotePublicKey);
    const currentRemotePublicKeyStr = this.remotePublicKey
      ? naclUtil.encodeBase64(this.remotePublicKey)
      : null;

    this.log("Remote public key from message:", remotePublicKeyStr);
    this.log("Stored remote public key:", currentRemotePublicKeyStr);

    if (
      !currentRemotePublicKeyStr ||
      remotePublicKeyStr !== currentRemotePublicKeyStr
    ) {
      this.log("New remote public key detected, performing DH ratchet");
      this.remotePublicKey = remotePublicKey;
      this.dhRatchetStep();
      this.messagesSinceLastReset = 0; // Reset the counter when a DH ratchet occurs
    } else {
      this.log("Remote public key unchanged, no DH ratchet needed");
    }

    const skippedKey = this.skippedMessageKeys.get(
      `${header.dhPubKey}:${header.messageIndex}`
    );
    if (skippedKey) {
      this.log("Using skipped message key:", naclUtil.encodeBase64(skippedKey));
      const plaintext = nacl.secretbox.open(ciphertext, nonce, skippedKey);
      if (plaintext) {
        this.skippedMessageKeys.delete(
          `${header.dhPubKey}:${header.messageIndex}`
        );
        return naclUtil.encodeUTF8(plaintext);
      }
    }

    if (header.messageIndex > this.receivingMessageNumber) {
      this.log(
        `Skipping ahead ${
          header.messageIndex - this.receivingMessageNumber
        } messages`
      );
      this.skipMessageKeys(header.messageIndex - this.receivingMessageNumber);
    } else if (header.messageIndex < this.receivingMessageNumber) {
      this.error(
        `Message index ${header.messageIndex} is less than expected ${this.receivingMessageNumber}`
      );
      throw new Error("Message index out of order");
    }

    if (!this.receivingChainKey) {
      this.error("receivingChainKey is null before decryption");
      throw new Error("receivingChainKey is null before decryption");
    }

    this.log(
      "Receiving chain key before deriving message key:",
      naclUtil.encodeBase64(this.receivingChainKey)
    );
    const derived = this.deriveMessageKey(this.receivingChainKey);
    this.receivingChainKey = derived.chainKey;
    const messageKey = derived.messageKey;

    this.log("Message decryption key:", naclUtil.encodeBase64(messageKey));
    this.log(
      "Receiving chain key after derivation:",
      naclUtil.encodeBase64(this.receivingChainKey)
    );

    const plaintext = nacl.secretbox.open(ciphertext, nonce, messageKey);
    if (!plaintext) {
      this.error("Failed to decrypt message: Invalid ciphertext or key");
      throw new Error("Decryption failed: Invalid ciphertext or key");
    }

    this.receivingMessageNumber++;
    this.messagesSinceLastReset++; // Increment counter for messages since last reset

    const decodedText = naclUtil.encodeUTF8(plaintext);
    this.log(`Successfully decrypted`);
    return decodedText;
  }

  skipMessageKeys(count) {
    if (count > this.MAX_SKIP) {
      this.error(`Too many skipped messages (${count} > ${this.MAX_SKIP})`);
      throw new Error(
        `Too many skipped messages (${count} > ${this.MAX_SKIP})`
      );
    }

    for (let i = 0; i < count; i++) {
      const derived = this.deriveMessageKey(this.receivingChainKey);
      this.receivingChainKey = derived.chainKey;

      const key = `${
        this.remotePublicKey
          ? naclUtil.encodeBase64(this.remotePublicKey)
          : "unknown"
      }:${this.receivingMessageNumber}`;
      this.skippedMessageKeys.set(key, derived.messageKey);
      this.receivingMessageNumber++;

      if (this.skippedMessageKeys.size > this.MAX_SKIP) {
        const oldestKey = Array.from(this.skippedMessageKeys.keys())[0];
        this.skippedMessageKeys.delete(oldestKey);
      }
    }
    this.log(
      "Skipped message keys, new receivingMessageNumber:",
      this.receivingMessageNumber
    );
  }

  getPublicKey() {
    return naclUtil.encodeBase64(this.dhKeyPair.publicKey);
  }

  getCurrentState() {
    return {
      rootKey: naclUtil.encodeBase64(this.rootKey),
      chainKey: naclUtil.encodeBase64(this.chainKey),
      sendingChainKey: this.sendingChainKey
        ? naclUtil.encodeBase64(this.sendingChainKey)
        : null,
      receivingChainKey: this.receivingChainKey
        ? naclUtil.encodeBase64(this.receivingChainKey)
        : null,
      sendingMessageNumber: this.sendingMessageNumber,
      receivingMessageNumber: this.receivingMessageNumber,
      messagesSinceLastReset: this.messagesSinceLastReset, // Save the messages counter
      dhKeyPair: {
        publicKey: naclUtil.encodeBase64(this.dhKeyPair.publicKey),
        secretKey: naclUtil.encodeBase64(this.dhKeyPair.secretKey),
      },
      remotePublicKey: this.remotePublicKey
        ? naclUtil.encodeBase64(this.remotePublicKey)
        : null,
    };
  }

  loadState(state) {
    this.rootKey = naclUtil.decodeBase64(state.rootKey);
    this.chainKey = naclUtil.decodeBase64(state.chainKey);
    this.sendingChainKey = state.sendingChainKey
      ? naclUtil.decodeBase64(state.sendingChainKey)
      : null;
    this.receivingChainKey = state.receivingChainKey
      ? naclUtil.decodeBase64(state.receivingChainKey)
      : null;
    this.sendingMessageNumber = state.sendingMessageNumber;
    this.receivingMessageNumber = state.receivingMessageNumber;
    this.messagesSinceLastReset = state.messagesSinceLastReset || 0; // Load counter with fallback
    this.dhKeyPair = {
      publicKey: naclUtil.decodeBase64(state.dhKeyPair.publicKey),
      secretKey: naclUtil.decodeBase64(state.dhKeyPair.secretKey),
    };
    this.remotePublicKey = state.remotePublicKey
      ? naclUtil.decodeBase64(state.remotePublicKey)
      : null;
  }
}

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB - increased for better image quality

const ChatScreen = ({ route, navigation }) => {
  const { width, height } = useWindowDimensions();
  const isSmallDevice = height < 700; // iPhone SE, small devices
  const isMediumDevice = height >= 700 && height < 800; // iPhone 13 mini, 12 mini
  const isLargeDevice = height >= 800; // iPhone 13, 12, 11, etc.

  // Get dynamic keyboard offset based on device size
  const getKeyboardOffset = () => {
    if (Platform.OS === "ios") {
      if (isSmallDevice) return 8;
      if (isMediumDevice) return 12;
      return 20; // for larger devices
    }
    return 0; // Android
  };

  // Calculate appropriate padding for input container
  const getInputPadding = () => {
    if (Platform.OS === "ios") {
      if (isSmallDevice) return 8;
      if (isMediumDevice) return 15;
      return 20; // for larger devices
    }
    return 15; // Android
  };

  // Calculate appropriate margin bottom for input container
  const getInputMargin = () => {
    if (Platform.OS === "ios") {
      if (isSmallDevice) return 5;
      if (isMediumDevice) return 10;
      return 15; // for larger devices
    }
    return 5; // Android
  };

  const {
    contact,
    userId: initialUserId,
    username: initialUsername,
  } = route.params || {};
  const contactData = {
    name: contact?.name || contact?.username || "Unknown",
    status: contact?.status || "offline",
  };

  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState("");
  const [isContactValid, setIsContactValid] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [currentUserId, setCurrentUserId] = useState(null);
  const [currentUsername, setCurrentUsername] = useState(null);
  const [ratchet, setRatchet] = useState(null);
  const [isImageModalVisible, setIsImageModalVisible] = useState(false);
  const [selectedImageUrl, setSelectedImageUrl] = useState(null);
  const flatListRef = useRef();
  const socketRef = useRef(null);
  const [isImageOptionsVisible, setIsImageOptionsVisible] = useState(false);
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [selectedMessage, setSelectedMessage] = useState(null);

  // Use a ref to track if message destruction setup has already been done
  const destructionSetupRef = useRef(false);

  // Add a ref to track messages already marked as seen to prevent duplicate API calls
  const seenMessagesRef = useRef(new Set());

  useEffect(() => {
    const initializeUser = async () => {
      let userId = initialUserId;
      let username = initialUsername;

      if (!userId || !username) {
        userId = await SecureStore.getItemAsync("userId");
        username = await SecureStore.getItemAsync("username");
      }

      if (!userId || !username) {
        Alert.alert(
          "Error",
          "User ID or username missing. Please log in again.",
          [
            {
              text: "OK",
              onPress: () =>
                navigation.reset({ index: 0, routes: [{ name: "Login" }] }),
            },
          ]
        );
        return;
      }

      setCurrentUserId(userId);
      setCurrentUsername(username);
      console.log("(NOBRIDGE) LOG Navigating to ChatScreen with:", {
        contactUsername: contactData.name,
        userId,
        username,
      });
    };

    initializeUser();
  }, [initialUserId, initialUsername, navigation]);

  useEffect(() => {
    const initializeRatchet = async () => {
      if (!currentUserId || !currentUsername) return;

      try {
        const ratchetStateStr = await SecureStore.getItemAsync(
          `ratchetState_${contactData.name}`
        );
        if (!ratchetStateStr) {
          throw new Error("Ratchet state not found for this contact.");
        }

        const ratchetState = JSON.parse(ratchetStateStr);
        console.log("(NOBRIDGE) LOG Loaded ratchet state:", ratchetState);

        const sharedSecret = naclUtil.decodeBase64(ratchetState.rootKey);
        const chainKey = naclUtil.decodeBase64(ratchetState.chainKey);
        const isInitiator = currentUsername < contactData.name;

        const dhKeyPair = {
          publicKey: naclUtil.decodeBase64(ratchetState.dhKeyPair.publicKey),
          secretKey: naclUtil.decodeBase64(ratchetState.dhKeyPair.privateKey),
        };

        const ratchetInstance = new DoubleRatchet(
          sharedSecret,
          chainKey,
          isInitiator,
          dhKeyPair
        ).setDebug(true);

        const updatedRatchetStateStr = await SecureStore.getItemAsync(
          `ratchetState_${contactData.name}_updated`
        );
        if (updatedRatchetStateStr) {
          const updatedRatchetState = JSON.parse(updatedRatchetStateStr);
          ratchetInstance.loadState(updatedRatchetState);
          console.log(
            "(NOBRIDGE) LOG Loaded updated ratchet state:",
            updatedRatchetState
          );
        } else {
          ratchetInstance.initializeSession(ratchetState.theirDhPubKey);
        }

        setRatchet(ratchetInstance);
      } catch (error) {
        console.error(
          "(NOBRIDGE) ERROR Failed to initialize ratchet:",
          String(error)
        );
        Alert.alert(
          "Error",
          "Failed to initialize encryption. Please re-establish contact."
        );
        navigation.goBack();
      }
    };

    initializeRatchet();
  }, [currentUserId, currentUsername, contactData.name, navigation]);

  useEffect(() => {
    return () => {
      // Cleanup on unmount
    };
  }, []);

  const saveImageToFileSystem = async (base64Data, messageId) => {
    try {
      const fileUri = `${FileSystem.documentDirectory}chat_images/${messageId}.jpg`;
      await FileSystem.makeDirectoryAsync(
        `${FileSystem.documentDirectory}chat_images`,
        { intermediates: true }
      );
      await FileSystem.writeAsStringAsync(fileUri, base64Data, {
        encoding: FileSystem.EncodingType.Base64,
      });
      return fileUri;
    } catch (error) {
      console.error(
        "(NOBRIDGE) ERROR Failed to save image to filesystem:",
        String(error)
      );
      return null;
    }
  };

  const loadLocalMessages = async () => {
    try {
      const storedMessages = await SecureStore.getItemAsync(
        `messages_${currentUsername}_${contactData.name}`
      );
      if (storedMessages) {
        console.log("(NOBRIDGE) LOG Loading stored messages from SecureStore");

        let parsedMessages;
        try {
          parsedMessages = JSON.parse(storedMessages);

          // Validate the parsed messages array
          if (!Array.isArray(parsedMessages)) {
            console.error(
              "(NOBRIDGE) ERROR Invalid messages format in storage - not an array"
            );
            await SecureStore.deleteItemAsync(
              `messages_${currentUsername}_${contactData.name}`
            );
            return [];
          }

          // Validate each message has required fields
          let validMessages = [];
          let fixedInvalidMessages = false;

          for (const msg of parsedMessages) {
            // Basic validation
            if (!msg.id) {
              console.error(
                "(NOBRIDGE) ERROR Invalid message in storage (missing id):",
                JSON.stringify(msg)
              );
              continue;
            }

            // Ensure message has proper time format
            let messageWithTime = { ...msg };

            // If message doesn't have a time property or it's "00:00", try to generate it
            if (!msg.time || msg.time === "00:00") {
              if (msg.sentAt) {
                const messageDate = new Date(msg.sentAt);
                messageWithTime.time = messageDate.toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  hour12: false,
                });
                console.log(
                  `(NOBRIDGE) LOG Fixed time for message ${msg.id}: ${messageWithTime.time} from sentAt ${msg.sentAt}`
                );
                fixedInvalidMessages = true;
              } else if (msg.timestamp) {
                const messageDate = new Date(msg.timestamp);
                messageWithTime.time = messageDate.toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  hour12: false,
                });
                console.log(
                  `(NOBRIDGE) LOG Fixed time for message ${msg.id}: ${messageWithTime.time} from timestamp ${msg.timestamp}`
                );
                fixedInvalidMessages = true;
              }
            }

            // Handle messages that need decryption (have ciphertext and nonce)
            if (msg.ciphertext && msg.nonce && !msg.isMe) {
              try {
                // Decrypt the message from secure storage
                const decrypted = await decryptMessageFromStorage(
                  messageWithTime
                );
                if (decrypted) {
                  validMessages.push(decrypted);
                }
              } catch (error) {
                console.error(
                  `(NOBRIDGE) ERROR Failed to decrypt message ${msg.id}: ${error.message}`
                );
                // Add the message anyway with empty text to preserve chat history
                validMessages.push({
                  ...messageWithTime,
                  isMe: false,
                  text: "[Message could not be decrypted]",
                  status: "received",
                });
              }
              continue;
            }

            // Fix messages missing isMe property
            if (msg.isMe === undefined) {
              console.error(
                "(NOBRIDGE) ERROR Invalid message in storage (missing isMe):",
                JSON.stringify(msg)
              );

              // Fix the message by setting isMe based on sender/receiver
              if (msg.sender && msg.receiver) {
                const isMe = msg.sender.username === currentUsername;
                validMessages.push({ ...messageWithTime, isMe });
                fixedInvalidMessages = true;
              }
              continue;
            }

            // Regular messages that don't need decryption
            validMessages.push(messageWithTime);
          }

          if (fixedInvalidMessages) {
            console.log(`(NOBRIDGE) LOG Fixed invalid messages in storage`);
            await saveLocalMessages(validMessages);
          }

          console.log(
            `(NOBRIDGE) LOG After validation: ${validMessages.length} valid messages`
          );

          // Check for expired messages
          validMessages = await checkForExpiredMessages(validMessages);

          // Sort messages by timestamp
          validMessages.sort((a, b) => {
            const timeA = a.timestamp || new Date(a.sentAt).getTime() || 0;
            const timeB = b.timestamp || new Date(b.sentAt).getTime() || 0;
            return timeA - timeB;
          });

          return validMessages;
        } catch (error) {
          console.error(
            "(NOBRIDGE) ERROR Error parsing stored messages:",
            error.message
          );
          return [];
        }
      } else {
        console.log("(NOBRIDGE) LOG No stored messages found");
        return [];
      }
    } catch (error) {
      console.error(
        "(NOBRIDGE) ERROR Error loading local messages:",
        error.message
      );
      return [];
    }
  };

  // Helper function to decrypt messages from secure storage
  const decryptMessageFromStorage = async (encryptedMessage) => {
    try {
      if (
        !encryptedMessage.ciphertext ||
        !encryptedMessage.nonce ||
        !encryptedMessage.headers
      ) {
        console.error(
          "(NOBRIDGE) ERROR Message missing required encryption data:",
          JSON.stringify({
            id: encryptedMessage.id,
            hasCiphertext: !!encryptedMessage.ciphertext,
            hasNonce: !!encryptedMessage.nonce,
            hasHeaders: !!encryptedMessage.headers,
          })
        );
        throw new Error("Message missing required encryption data");
      }

      console.log(
        "(NOBRIDGE) LOG Decrypting message with header:",
        JSON.stringify(encryptedMessage.headers)
      );

      // Convert headers format if needed
      // DoubleRatchet.decrypt expects a specific format with header object
      const header = encryptedMessage.headers || {};

      // Ensure we have the critical dhPubKey property
      if (!header.dhPubKey) {
        console.error(
          "(NOBRIDGE) ERROR Missing dhPubKey in message headers for message:",
          encryptedMessage.id
        );
        throw new Error("Missing dhPubKey in message headers");
      }

      // Use the ratchet to decrypt the message
      const decrypted = await ratchet.decrypt({
        header: header, // Use the properly formatted header
        ciphertext: encryptedMessage.ciphertext,
        nonce: encryptedMessage.nonce,
      });

      // Format timestamp for display
      let formattedTime = "00:00";
      if (encryptedMessage.sentAt) {
        const messageDate = new Date(encryptedMessage.sentAt);
        formattedTime = messageDate.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        });
        console.log(
          `(NOBRIDGE) LOG Formatted time for message ${encryptedMessage.id}: ${formattedTime} from ${encryptedMessage.sentAt}`
        );
      } else if (encryptedMessage.timestamp) {
        const messageDate = new Date(encryptedMessage.timestamp);
        formattedTime = messageDate.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        });
        console.log(
          `(NOBRIDGE) LOG Formatted time for message ${encryptedMessage.id}: ${formattedTime} from timestamp ${encryptedMessage.timestamp}`
        );
      }

      // Return a properly formatted message with the decrypted text
      return {
        ...encryptedMessage,
        text: decrypted,
        isMe: false,
        status: "seen",
        time: formattedTime,
      };
    } catch (error) {
      console.error(
        `(NOBRIDGE) ERROR Failed to decrypt message ${encryptedMessage.id}: ${error.message}`
      );
      throw error;
    }
  };

  const saveLocalMessages = async (msgs) => {
    try {
      const validMessages = msgs
        .filter((msg) => {
          if (!msg.id || typeof msg.isMe === "undefined") {
            // Only log errors for invalid messages in development
            /*
            console.error(
              "(NOBRIDGE) ERROR Attempting to save invalid message (missing id or isMe):",
              msg
            );
            */
            return false;
          }

          // Safety check: Normalize message fields to prevent undefined values
          if (msg.text === undefined) {
            // Add a fallback text value if undefined - no need to log this
            // console.log(
            //   "(NOBRIDGE) LOG Fixing message with undefined text:",
            //   msg.id
            // );
            msg.text = msg.isMe ? "Message sent" : "[Message content missing]";
          }

          // A message should have either text or image data/path after normalization
          if (!msg.text && !msg.imageData && !msg.imagePath) {
            /*
            console.error(
              "(NOBRIDGE) ERROR Attempting to save empty message:",
              msg
            );
            */
            return false;
          }
          return true;
        })
        .map((msg) => ({
          id: msg.id,
          text: msg.text || null,
          imagePath: msg.imagePath || null,
          time: msg.time || "00:00",
          isMe: msg.isMe,
          timestamp: msg.timestamp || Date.now(),
          seen: msg.seen || false,
          seenAt: msg.seenAt || null,
          status: msg.status || "sent",
        }));

      await SecureStore.setItemAsync(
        `messages_${currentUsername}_${contactData.name}`,
        JSON.stringify(validMessages)
      );
    } catch (error) {
      console.error(
        "(NOBRIDGE) ERROR Failed to save local messages:",
        String(error)
      );
    }
  };

  const saveRatchetState = async () => {
    if (ratchet) {
      try {
        const updatedState = ratchet.getCurrentState();
        await SecureStore.setItemAsync(
          `ratchetState_${contactData.name}_updated`,
          JSON.stringify(updatedState)
        );
        console.log(
          "(NOBRIDGE) LOG Saved updated ratchet state:",
          updatedState
        );
      } catch (error) {
        console.error(
          "(NOBRIDGE) ERROR Failed to save ratchet state:",
          String(error)
        );
      }
    }
  };

  useEffect(() => {
    if (!currentUserId || !ratchet) return;

    const initializeSocket = async () => {
      const authToken = await SecureStore.getItemAsync("token");
      if (!authToken) {
        Alert.alert("Error", "Authentication token missing", [
          {
            text: "OK",
            onPress: () =>
              navigation.reset({ index: 0, routes: [{ name: "Login" }] }),
          },
        ]);
        return;
      }

      socketRef.current = io(CONFIG.BACKEND_URL, {
        auth: { token: authToken },
        reconnection: true,
        reconnectionAttempts: 10,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        timeout: 15000,
        forceNew: false,
      });

      socketRef.current.on("connect", () => {
        console.log("(NOBRIDGE) LOG Socket.IO connected");

        // Ensure we register immediately on connection
        if (currentUserId) {
          socketRef.current.emit("register", currentUserId.toString());
          console.log(
            `(NOBRIDGE) LOG User ${currentUserId} registered as online from ChatScreen`
          );

          // When viewing a chat, notify the server to mark messages as delivered
          if (contactData && contactData.name) {
            socketRef.current.emit("viewing_chat", {
              contactId: contactData._id || contactData.id || contactData.name,
            });
            console.log(
              `(NOBRIDGE) LOG Emitted viewing_chat for contact: ${contactData.name}`
            );
          }
        }
      });

      // Set up a reconnect listener for additional logging
      socketRef.current.on("reconnect", (attemptNumber) => {
        console.log(
          `(NOBRIDGE) LOG Socket reconnected after ${attemptNumber} attempts`
        );

        // Re-register after reconnection
        if (currentUserId) {
          socketRef.current.emit("register", currentUserId.toString());
          console.log(
            `(NOBRIDGE) LOG User ${currentUserId} re-registered after reconnection`
          );

          // Also re-emit viewing_chat
          if (contactData && contactData.name) {
            socketRef.current.emit("viewing_chat", {
              contactId: contactData._id || contactData.id || contactData.name,
            });
            console.log(
              `(NOBRIDGE) LOG Re-emitted viewing_chat after reconnection`
            );
          }
        }
      });

      // Also set up a reconnect_attempt listener
      socketRef.current.on("reconnect_attempt", (attemptNumber) => {
        console.log(
          `(NOBRIDGE) LOG Socket reconnect attempt #${attemptNumber}`
        );
      });

      // When viewing a chat, notify the server to mark messages as delivered
      // This is in addition to the one in connect to ensure it's always sent
      if (contactData && contactData.name) {
        socketRef.current.emit("viewing_chat", {
          contactId: contactData._id || contactData.id || contactData.name,
        });
        console.log(
          `(NOBRIDGE) LOG Initially emitted viewing_chat for contact: ${contactData.name}`
        );
      }

      // Add proper focus and blur listeners
      const focusUnsubscribe = navigation.addListener("focus", () => {
        console.log("(NOBRIDGE) LOG ChatScreen focused");
        if (socketRef.current && socketRef.current.connected && currentUserId) {
          // Make sure we're registered as online
          socketRef.current.emit("register", currentUserId.toString());

          // Notify server we're viewing this chat
          if (contactData && contactData.name) {
            socketRef.current.emit("viewing_chat", {
              contactId: contactData._id || contactData.id || contactData.name,
            });
            console.log(
              `(NOBRIDGE) LOG Re-emitted viewing_chat on focus: ${contactData.name}`
            );
          }
        } else if (
          socketRef.current &&
          !socketRef.current.connected &&
          currentUserId
        ) {
          console.log("(NOBRIDGE) LOG Socket disconnected - reconnecting...");
          // Try to reconnect if somehow disconnected
          socketRef.current.connect();

          // Re-register after a short delay to ensure connection is established
          setTimeout(() => {
            if (socketRef.current && socketRef.current.connected) {
              socketRef.current.emit("register", currentUserId.toString());
              console.log(
                `(NOBRIDGE) LOG Re-registered user ${currentUserId} after reconnection`
              );

              // Re-emit viewing_chat as well
              if (contactData && contactData.name) {
                socketRef.current.emit("viewing_chat", {
                  contactId:
                    contactData._id || contactData.id || contactData.name,
                });
                console.log(
                  `(NOBRIDGE) LOG Re-emitted viewing_chat after reconnection`
                );
              }
            }
          }, 1000);
        }
      });

      const blurUnsubscribe = navigation.addListener("blur", () => {
        console.log("(NOBRIDGE) LOG ChatScreen blurred");
        if (socketRef.current && socketRef.current.connected) {
          // Tell the server we're leaving this chat
          socketRef.current.emit("leaving_chat");
          console.log("(NOBRIDGE) LOG Emitted leaving_chat on blur");
        }
      });

      socketRef.current.on("newMessage", async (message) => {
        console.log("(NOBRIDGE) LOG Received newMessage event:", message);
        if (
          !message ||
          typeof message !== "object" ||
          !message._id ||
          !message.sender ||
          !message.sender._id ||
          !message.sender.username ||
          !message.receiver ||
          !message.receiver.username ||
          !message.headers ||
          !message.ciphertext ||
          !message.nonce ||
          !message.sentAt
        ) {
          console.error(
            "(NOBRIDGE) ERROR Invalid message received via socket:",
            message
          );
          return;
        }

        if (
          message.sender.username === contactData.name ||
          message.receiver.username === contactData.name
        ) {
          // For chat with this contact
          try {
            // Store the message in SecureStore first
            const isMe = message.sender._id === currentUserId;
            const storedMessages = await SecureStore.getItemAsync(
              `messages_${currentUsername}_${contactData.name}`
            );
            let messagesArray = storedMessages
              ? JSON.parse(storedMessages)
              : [];

            // Make sure we don't already have this message
            if (!messagesArray.some((msg) => msg.id === message._id)) {
              // Format proper time for the message
              const messageDate = new Date(message.sentAt);
              const formattedTime = messageDate.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                hour12: false,
              });

              console.log(
                `(NOBRIDGE) LOG Formatted time for incoming message: ${formattedTime} from ${message.sentAt}`
              );

              // Store COMPLETE message with all header information intact
              const newMessage = {
                id: message._id,
                text: "",
                ciphertext: message.ciphertext,
                nonce: message.nonce,
                headers: message.headers, // Store complete headers
                timestamp: new Date(message.sentAt).getTime(),
                sentAt: message.sentAt,
                time: formattedTime,
                sender: { username: message.sender.username },
                receiver: { username: message.receiver.username },
                isMe: isMe,
                read: false,
                status: message.status || "sent",
              };

              // Add message to stored messages
              messagesArray.push(newMessage);
              await SecureStore.setItemAsync(
                `messages_${currentUsername}_${contactData.name}`,
                JSON.stringify(messagesArray)
              );

              console.log(
                `(NOBRIDGE) LOG Stored incoming message ${message._id} from socket in SecureStore`
              );

              let displayMessage = { ...newMessage };

              // If it's an incoming message, mark as delivered and decrypt
              if (!isMe) {
                try {
                  // Always mark as delivered first (this clears sensitive data on server)
                  const authToken = await SecureStore.getItemAsync("token");
                  if (authToken) {
                    await axios.patch(
                      `${CONFIG.BACKEND_URL}/api/messages/${message._id}/delivered`,
                      {},
                      {
                        headers: { Authorization: `Bearer ${authToken}` },
                      }
                    );
                    console.log(
                      `(NOBRIDGE) LOG Marked message ${message._id} as delivered on server`
                    );
                  }

                  // Decrypt from the locally stored copy
                  const decrypted = await decryptMessageFromStorage(newMessage);
                  displayMessage = {
                    ...displayMessage,
                    text: decrypted.text,
                    time: formattedTime,
                  };

                  console.log(
                    "(NOBRIDGE) LOG Successfully decrypted incoming message"
                  );
                } catch (error) {
                  console.error(
                    "(NOBRIDGE) ERROR Failed to decrypt or mark as delivered:",
                    error.message
                  );
                  displayMessage.text = "[Message could not be decrypted]";
                }
              }

              // Add to UI
              setMessages((prevMessages) => [...prevMessages, displayMessage]);

              // Update in storage with any changes (e.g., decrypted text)
              messagesArray[messagesArray.length - 1] = {
                ...newMessage,
                text: displayMessage.text,
              };
              await SecureStore.setItemAsync(
                `messages_${currentUsername}_${contactData.name}`,
                JSON.stringify(messagesArray)
              );

              // Scroll to the end
              setTimeout(() => {
                flatListRef.current?.scrollToEnd({ animated: true });
              }, 100);
            }
          } catch (error) {
            console.error(
              "(NOBRIDGE) ERROR Error processing incoming message:",
              error.message
            );
          }
        }
      });

      // Handle message status updates (delivered, seen, expired)
      socketRef.current.on("messageStatusUpdate", async (statusUpdate) => {
        console.log(
          "(NOBRIDGE) LOG Received messageStatusUpdate:",
          statusUpdate
        );

        if (!statusUpdate || !statusUpdate.messageId || !statusUpdate.status) {
          console.error(
            "(NOBRIDGE) ERROR Invalid status update:",
            statusUpdate
          );
          return;
        }

        try {
          // Log status update in a more visible way
          console.log(
            `⭐️ STATUS UPDATE: ${statusUpdate.messageId} → ${statusUpdate.status} ⭐️`
          );

          // APPROACH 1: Direct state update with forced re-render
          // This ensures immediate UI update
          setMessages((prevMessages) => {
            // Log existing message before update
            const existingMessage = prevMessages.find(
              (msg) => msg.id === statusUpdate.messageId
            );

            if (existingMessage) {
              console.log(
                `(NOBRIDGE) LOG Found message to update: ${existingMessage.id} [${existingMessage.status} → ${statusUpdate.status}]`
              );
            } else {
              console.log(
                `(NOBRIDGE) ERROR Could not find message: ${statusUpdate.messageId}`
              );
              return prevMessages; // No changes needed
            }

            // Create a new array with the updated message
            const updatedMessages = prevMessages.map((msg) =>
              msg.id === statusUpdate.messageId
                ? {
                    ...msg,
                    status: statusUpdate.status,
                    deliveredAt: statusUpdate.deliveredAt || msg.deliveredAt,
                    seenAt: statusUpdate.seenAt || msg.seenAt,
                  }
                : msg
            );

            // Save to local storage immediately
            saveLocalMessages(updatedMessages);

            return updatedMessages;
          });

          // APPROACH 2: Force a complete refresh after a brief delay
          // This is a backup approach to ensure the UI updates
          setTimeout(() => {
            setMessages((prevMessages) => {
              // Create a new copy of the current messages
              return [...prevMessages];
            });
          }, 300);

          // APPROACH 3: Extreme refresh - recreate the entire message list
          // This is the final fallback if all else fails
          setTimeout(() => {
            // Reload messages from storage
            loadLocalMessages().then((storedMessages) => {
              if (storedMessages && storedMessages.length > 0) {
                // Only update if we got messages back
                setMessages(storedMessages);
              }
            });
          }, 1000);

          // If the status is "seen", acknowledge to the server that we've seen it
          if (statusUpdate.status === "seen") {
            try {
              console.log(
                `(NOBRIDGE) LOG Acknowledging seen status for message ${statusUpdate.messageId}`
              );

              // First, emit socket event to acknowledge the status
              socketRef.current.emit("acknowledge_status", {
                messageId: statusUpdate.messageId,
              });

              // Then, send an API call to acknowledge (as backup)
              const authToken = await SecureStore.getItemAsync("token");
              if (authToken) {
                try {
                  await axios.patch(
                    `${CONFIG.BACKEND_URL}/api/messages/${statusUpdate.messageId}/acknowledge`,
                    {},
                    { headers: { Authorization: `Bearer ${authToken}` } }
                  );
                  console.log(
                    `(NOBRIDGE) LOG API acknowledgment sent for message ${statusUpdate.messageId}`
                  );
                } catch (apiError) {
                  // If it's a 404, the message might already be deleted, which is fine
                  if (apiError.response && apiError.response.status === 404) {
                    console.log(
                      `(NOBRIDGE) LOG Message ${statusUpdate.messageId} already deleted from server`
                    );
                  } else {
                    console.error(
                      "(NOBRIDGE) ERROR API acknowledgment failed:",
                      apiError
                    );
                  }
                }
              }
            } catch (ackError) {
              console.error(
                "(NOBRIDGE) ERROR Failed to acknowledge message status:",
                ackError
              );
            }
          }
        } catch (error) {
          console.error(
            "(NOBRIDGE) ERROR Failed to update message status:",
            error
          );
        }
      });

      socketRef.current.on("connect_error", (error) => {
        console.error(
          "(NOBRIDGE) ERROR Socket connection error:",
          String(error)
        );
      });

      socketRef.current.on("disconnect", (reason) => {
        console.log("(NOBRIDGE) LOG Socket disconnected:", reason);
        if (reason === "io server disconnect") {
          socketRef.current.connect();
        }
      });

      // Add listener for message_acknowledged event to immediately update status
      socketRef.current.on("message_acknowledged", (ack) => {
        console.log("(NOBRIDGE) LOG Received message_acknowledged:", ack);

        if (!ack || !ack.messageId || !ack.status) {
          console.error("(NOBRIDGE) ERROR Invalid acknowledgment:", ack);
          return;
        }

        try {
          // Log status update in a more visible way
          console.log(
            `⭐️ MESSAGE ACKNOWLEDGED: ${ack.messageId} → ${ack.status} ⭐️`
          );

          // APPROACH 1: Direct state update with forced re-render
          // This ensures immediate UI update
          setMessages((prevMessages) => {
            // Log existing message before update
            const existingMessage = prevMessages.find(
              (msg) => msg.id === ack.messageId
            );

            if (existingMessage) {
              console.log(
                `(NOBRIDGE) LOG Found message to update: ${existingMessage.id} [${existingMessage.status} → ${ack.status}]`
              );
            } else {
              console.log(
                `(NOBRIDGE) ERROR Could not find message: ${ack.messageId}`
              );
              return prevMessages; // No changes needed
            }

            // Create a new array with the updated message
            const updatedMessages = prevMessages.map((msg) =>
              msg.id === ack.messageId
                ? {
                    ...msg,
                    status: ack.status,
                    sentAt: ack.sentAt || msg.sentAt,
                  }
                : msg
            );

            // Save to local storage immediately
            saveLocalMessages(updatedMessages);

            return updatedMessages;
          });

          // Also use backup approaches to ensure UI updates
          setTimeout(() => {
            setMessages((prevMessages) => [...prevMessages]);
          }, 300);
        } catch (error) {
          console.error(
            "(NOBRIDGE) ERROR Failed to update message status:",
            error
          );
        }
      });

      // Add handler for message_deleted event
      socketRef.current.on("message_deleted", async ({ messageId }) => {
        console.log(`(NOBRIDGE) LOG Message deleted from server: ${messageId}`);

        // We're only deleting messages from the server, not the UI
        // No need to remove from local state or storage
        console.log(
          `(NOBRIDGE) LOG Message ${messageId} deleted from server but kept in UI`
        );
      });

      // Add cleanup for leaving_chat event
      return () => {
        focusUnsubscribe();
        blurUnsubscribe();

        if (socketRef.current) {
          // Emit leaving_chat event when leaving the chat screen
          socketRef.current.emit("leaving_chat");
          console.log("(NOBRIDGE) LOG Emitted leaving_chat event");

          socketRef.current.disconnect();
          socketRef.current = null;
        }
      };
    };

    initializeSocket();

    return () => {
      if (socketRef.current) {
        // Emit leaving_chat event when unmounting
        socketRef.current.emit("leaving_chat");
        console.log("(NOBRIDGE) LOG Emitted leaving_chat event on unmount");

        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, [currentUserId, contactData.name, ratchet, navigation]);

  const checkContactStatus = async () => {
    if (!currentUserId || !currentUsername) {
      console.error(
        "(NOBRIDGE) ERROR ChatScreen - checkContactStatus: Missing currentUserId or currentUsername"
      );
      return;
    }

    setIsLoading(true);
    try {
      const authToken = await SecureStore.getItemAsync("token");
      if (!authToken) throw new Error("Authentication token missing");

      const storedContacts = await SecureStore.getItemAsync(
        `${currentUsername}_contacts`
      );
      const contactsList = storedContacts ? JSON.parse(storedContacts) : [];
      console.log(
        "(NOBRIDGE) LOG Checking chat access - Stored contacts:",
        contactsList
      );
      console.log("(NOBRIDGE) LOG Attempting to chat with:", contactData.name);
      if (!contactsList.includes(contactData.name)) {
        throw new Error("Not a contact");
      }

      const invitesResponse = await axios.get(
        `${CONFIG.BACKEND_URL}/api/invites/received`,
        {
          headers: { Authorization: `Bearer ${authToken}` },
        }
      );

      const removedInvite = invitesResponse.data.find(
        (invite) =>
          (invite.sender?.username === contactData.name ||
            invite.receiver?.username === contactData.name) &&
          invite.status === "removed"
      );
      if (removedInvite) throw new Error("Contact has been removed");

      setIsContactValid(true);

      // First check if there are any new messages on the server that we don't have locally
      try {
        console.log("(NOBRIDGE) LOG Checking for new messages on server");
        const messagesResponse = await axios.get(
          `${CONFIG.BACKEND_URL}/api/messages`,
          {
            headers: { Authorization: `Bearer ${authToken}` },
            timeout: 5000,
          }
        );

        const serverMessages = messagesResponse.data;
        if (Array.isArray(serverMessages) && serverMessages.length > 0) {
          // Filter for messages from/to this contact
          const relevantMessages = serverMessages.filter(
            (msg) =>
              (msg.sender.username === contactData.name &&
                msg.receiver.username === currentUsername) ||
              (msg.sender.username === currentUsername &&
                msg.receiver.username === contactData.name)
          );

          if (relevantMessages.length > 0) {
            console.log(
              `(NOBRIDGE) LOG Found ${relevantMessages.length} messages for this contact on server`
            );

            // Get existing local messages
            const messagesKey = `messages_${currentUsername}_${contactData.name}`;
            const storedMessagesStr = await SecureStore.getItemAsync(
              messagesKey
            );
            let storedMessages = storedMessagesStr
              ? JSON.parse(storedMessagesStr)
              : [];

            let messagesAdded = false;

            // Process each message
            for (const serverMsg of relevantMessages) {
              // Check if we already have this message
              const existingMsgIndex = storedMessages.findIndex(
                (msg) => msg.id === serverMsg._id
              );

              if (existingMsgIndex === -1 && serverMsg.status === "sent") {
                // This is a new message, store it locally
                console.log(
                  `(NOBRIDGE) LOG Storing new message ${serverMsg._id} from server`
                );

                const newMessage = {
                  id: serverMsg._id,
                  text: serverMsg.text || "",
                  ciphertext: serverMsg.ciphertext,
                  nonce: serverMsg.nonce,
                  headers: serverMsg.headers,
                  type: serverMsg.type || "text",
                  sender: { username: serverMsg.sender.username },
                  receiver: { username: serverMsg.receiver.username },
                  sentAt: serverMsg.sentAt,
                  timestamp: new Date(serverMsg.sentAt).getTime(),
                  isMe: serverMsg.sender.username === currentUsername,
                  status: "delivered",
                };

                storedMessages.push(newMessage);
                messagesAdded = true;

                // Mark as delivered on server
                try {
                  await axios.patch(
                    `${CONFIG.BACKEND_URL}/api/messages/${serverMsg._id}/delivered`,
                    {},
                    { headers: { Authorization: `Bearer ${authToken}` } }
                  );
                  console.log(
                    `(NOBRIDGE) LOG Marked message ${serverMsg._id} as delivered on server`
                  );
                } catch (err) {
                  console.error(
                    `(NOBRIDGE) ERROR Failed to mark as delivered: ${err.message}`
                  );
                }
              }
            }

            // Save updated messages list if we added any
            if (messagesAdded) {
              await SecureStore.setItemAsync(
                messagesKey,
                JSON.stringify(storedMessages)
              );
              console.log(
                "(NOBRIDGE) LOG Updated local message store with new messages from server"
              );
            }
          }
        }
      } catch (error) {
        console.error(
          "(NOBRIDGE) ERROR Failed to check for new messages:",
          error.message
        );
        // Continue even if this check fails
      }

      // Now load messages from secure storage
      const decryptedMessages = await loadLocalMessages();

      // Set messages and scroll to end
      setMessages(decryptedMessages);

      // Mark all unread messages as read
      await markAllAsRead();

      if (decryptedMessages.length > 0) {
        setTimeout(() => {
          flatListRef.current?.scrollToEnd({ animated: false });
        }, 100);
      }

      setIsLoading(false);
    } catch (error) {
      const errorMessage =
        error instanceof Error
          ? error.message
          : String(error) || "Unknown error occurred";
      console.error(
        "(NOBRIDGE) ERROR ChatScreen - checkContactStatus error:",
        errorMessage
      );

      if (error.response?.status === 401) {
        Alert.alert("Error", "Session expired. Please log in again.", [
          {
            text: "OK",
            onPress: async () => {
              await SecureStore.deleteItemAsync("token");
              navigation.reset({ index: 0, routes: [{ name: "Login" }] });
            },
          },
        ]);
      } else {
        Alert.alert(
          "Error",
          errorMessage === "Not a contact"
            ? "You can only chat with accepted contacts."
            : errorMessage === "Contact has been removed"
            ? "This contact is no longer available."
            : `Failed to load chat: ${errorMessage}`
        );
        navigation.goBack();
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Helper function to mark all unread messages from this contact as read
  const markAllAsRead = async () => {
    try {
      // Get current messages from secure storage
      const storedMessages = await SecureStore.getItemAsync(
        `messages_${currentUsername}_${contactData.name}`
      );
      if (!storedMessages) return;

      const parsedMessages = JSON.parse(storedMessages);
      let hasChanges = false;
      const seenUpdates = [];
      const now = Date.now();

      // Update messages to mark them as seen
      const updatedMessages = parsedMessages.map((msg) => {
        // Only mark received messages (not our own) and not already seen
        if (!msg.isMe && msg.status !== "seen") {
          hasChanges = true;

          // Keep track of messages we need to update on the server
          seenUpdates.push(msg.id);

          return {
            ...msg,
            status: "seen",
            seenAt: now,
          };
        }
        return msg;
      });

      // If changes were made, save back to secure storage
      if (hasChanges) {
        await SecureStore.setItemAsync(
          `messages_${currentUsername}_${contactData.name}`,
          JSON.stringify(updatedMessages)
        );
        console.log(
          `(NOBRIDGE) LOG Marked ${seenUpdates.length} messages as seen in secure storage`
        );

        // Update server for each message
        const authToken = await SecureStore.getItemAsync("token");
        if (authToken) {
          for (const messageId of seenUpdates) {
            try {
              await axios.patch(
                `${CONFIG.BACKEND_URL}/api/messages/${messageId}/read`,
                {},
                { headers: { Authorization: `Bearer ${authToken}` } }
              );
              console.log(
                `(NOBRIDGE) LOG Marked message ${messageId} as seen on server`
              );

              // Add to seen messages ref to prevent duplicate API calls
              seenMessagesRef.current.add(messageId);
            } catch (error) {
              // If it's a 404, the message was probably already deleted from the server
              if (error.response && error.response.status === 404) {
                console.log(
                  `(NOBRIDGE) LOG Message ${messageId} already deleted from server`
                );
              } else {
                console.error(
                  `(NOBRIDGE) ERROR Failed to mark message ${messageId} as seen on server: ${error.message}`
                );
              }
            }
          }
        }
      }
    } catch (error) {
      console.error("(NOBRIDGE) ERROR Failed to mark messages as seen:", error);
    }
  };

  useEffect(() => {
    if (currentUserId && currentUsername && ratchet) {
      checkContactStatus();
    }
  }, [currentUserId, currentUsername, ratchet, contactData.name]);

  const handleImageOption = async (option) => {
    try {
      setIsImageOptionsVisible(false);
      await new Promise((resolve) => setTimeout(resolve, 500));

      let result;
      if (option === "library") {
        const { status } =
          await ImagePicker.requestMediaLibraryPermissionsAsync();
        if (status !== "granted") {
          Alert.alert(
            "Permission required",
            "Need permission to access your photos"
          );
          return;
        }

        result = await ImagePicker.launchImageLibraryAsync({
          mediaTypes: ["images"],
          quality: 0.8,
          allowsEditing: true,
          aspect: [4, 3],
        });
      } else if (option === "camera") {
        const { status } = await ImagePicker.requestCameraPermissionsAsync();
        if (status !== "granted") {
          Alert.alert(
            "Permission required",
            "Need permission to access your camera"
          );
          return;
        }

        result = await ImagePicker.launchCameraAsync({
          mediaTypes: ["images"],
          quality: 0.8,
          allowsEditing: true,
          aspect: [4, 3],
        });
      }

      if (!result.canceled && result.assets && result.assets.length > 0) {
        const asset = result.assets[0];
        processAndSendImage(asset.uri);
      }
    } catch (error) {
      console.error("(NOBRIDGE) ERROR Image picker:", error);
      Alert.alert("Error", "Could not access photos/camera");
    }
  };

  const processAndSendImage = async (uri) => {
    try {
      if (!uri) return;

      const manipResult = await ImageManipulator.manipulateAsync(
        uri,
        [{ resize: { width: 700 } }],
        {
          compress: 0.2,
          format: ImageManipulator.SaveFormat.JPEG,
          base64: true,
        }
      );

      if (manipResult.base64) {
        const imageSize = manipResult.base64.length * 0.75;
        if (imageSize > MAX_FILE_SIZE) {
          const compressedResult = await ImageManipulator.manipulateAsync(
            uri,
            [{ resize: { width: 800 } }],
            {
              compress: 0.2,
              format: ImageManipulator.SaveFormat.JPEG,
              base64: true,
            }
          );

          if (compressedResult.base64.length * 0.75 > MAX_FILE_SIZE) {
            Alert.alert(
              "Error",
              "Image is too large. Please use a smaller image."
            );
            return;
          }

          await sendImage(compressedResult.base64);
        } else {
          await sendImage(manipResult.base64);
        }
      }
    } catch (error) {
      console.error("(NOBRIDGE) ERROR Processing image:", error);
      Alert.alert("Error", "Failed to process image");
    }
  };

  const sendImage = async (base64Data) => {
    if (!isContactValid || !ratchet) return;

    try {
      const authToken = await SecureStore.getItemAsync("token");
      if (!authToken) throw new Error("Authentication token missing");

      const imageData = `data:image/jpeg;base64,${base64Data}`;
      const tempId = uuidv4();
      const imagePath = await saveImageToFileSystem(base64Data, tempId);

      // Format current time properly
      const now = new Date();
      const formattedTime = now.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });

      console.log(
        `(NOBRIDGE) LOG Formatted time for image message: ${formattedTime}`
      );

      const newMsg = {
        id: tempId,
        text: null,
        imageData,
        imagePath,
        time: formattedTime,
        isMe: true,
        timestamp: now.getTime(),
        sentAt: now.toISOString(),
        status: "sent", // Initial status is "sent"
      };

      setMessages((prev) => {
        const updatedMessages = [...prev, newMsg];
        saveLocalMessages(updatedMessages);
        return updatedMessages;
      });

      const encryptedMessage = await ratchet.encrypt(imageData);
      // Set a very far future expiration date (approx. 10 years) to effectively keep messages forever
      const expiresAt = new Date(
        Date.now() + 10 * 365 * 24 * 60 * 60 * 1000 // 10 years
      ).toISOString();

      const response = await axios.post(
        `${CONFIG.BACKEND_URL}/api/messages/send`,
        {
          receiver: contactData.name,
          ciphertext: encryptedMessage.ciphertext,
          nonce: encryptedMessage.nonce,
          headers: {
            dhPubKey: encryptedMessage.header.dhPubKey,
            messageIndex: encryptedMessage.header.messageIndex,
            prevChainLength: encryptedMessage.header.prevChainLength,
          },
          type: "image",
          expiresAt,
        },
        {
          headers: { Authorization: `Bearer ${authToken}` },
          timeout: 30000,
        }
      );

      const finalImagePath = await saveImageToFileSystem(
        base64Data,
        response.data._id
      );

      // Format server timestamp
      const serverTime = new Date(response.data.sentAt).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });

      console.log(
        `(NOBRIDGE) LOG Server timestamp for image: ${serverTime} from ${response.data.sentAt}`
      );

      setMessages((prev) => {
        const updatedMessages = prev.map((msg) =>
          msg.id === tempId
            ? {
                id: response.data._id.toString(),
                text: null,
                imageData,
                imagePath: finalImagePath,
                time: serverTime,
                isMe: true,
                timestamp: new Date(response.data.sentAt).getTime(),
                sentAt: response.data.sentAt,
                status: response.data.status || "sent",
              }
            : msg
        );
        saveLocalMessages(updatedMessages);
        return updatedMessages;
      });

      if (imagePath !== finalImagePath) {
        await FileSystem.deleteAsync(imagePath, { idempotent: true });
      }

      await saveRatchetState();

      setTimeout(() => {
        flatListRef.current?.scrollToEnd({ animated: true });
      }, 100);
    } catch (error) {
      console.error("(NOBRIDGE) ERROR Sending image:", error);
      Alert.alert("Error", "Failed to send image");
    }
  };

  const handleDeleteMessage = async (messageId) => {
    try {
      if (!messageId) return;
      console.log("(NOBRIDGE) LOG Deleting message:", messageId);

      // Get the current messages from SecureStore
      const messagesKey = `messages_${currentUsername}_${contactData.name}`;
      const storedMessagesJson = await SecureStore.getItemAsync(messagesKey);

      if (storedMessagesJson) {
        const storedMessages = JSON.parse(storedMessagesJson);

        // Filter out the message to delete
        const updatedMessages = storedMessages.filter(
          (msg) => msg.id !== messageId
        );

        // Save updated messages back to SecureStore
        await SecureStore.setItemAsync(
          messagesKey,
          JSON.stringify(updatedMessages)
        );
        console.log(
          `(NOBRIDGE) LOG Removed message ${messageId} from SecureStore`
        );

        // Update state to remove the message from UI
        setMessages((prevMessages) =>
          prevMessages.filter((msg) => msg.id !== messageId)
        );
      }

      // Also try to delete from server if it exists there
      try {
        const authToken = await SecureStore.getItemAsync("token");
        if (authToken) {
          await axios.delete(
            `${CONFIG.BACKEND_URL}/api/messages/${messageId}`,
            {
              headers: { Authorization: `Bearer ${authToken}` },
            }
          );
          console.log(
            `(NOBRIDGE) LOG Deleted message ${messageId} from server`
          );
        }
      } catch (serverError) {
        console.log(
          `(NOBRIDGE) LOG Message ${messageId} not found on server or already deleted`
        );
        // Continue even if server deletion fails - might not be on server
      }

      // Close the modal
      setSelectedMessage(null);
      setDeleteModalVisible(false);
    } catch (error) {
      console.error("(NOBRIDGE) ERROR Failed to delete message:", error);
      Alert.alert("Error", "Failed to delete message");
    }
  };

  const renderMessage = ({ item }) => {
    // Check if the message is valid
    const isValidMessage = item && item.id && (item.text || item.imageData);

    if (!isValidMessage) {
      console.log(
        "(NOBRIDGE) LOG Skipping invalid message in render:",
        item?.id || "unknown"
      );
      return null;
    }

    // Ensure message has a valid time
    let displayTime = item.time || "00:00";

    // If time is missing or invalid, try to generate it from sentAt or timestamp
    if (!displayTime || displayTime === "00:00") {
      if (item.sentAt) {
        const messageDate = new Date(item.sentAt);
        displayTime = messageDate.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        });
      } else if (item.timestamp) {
        const messageDate = new Date(item.timestamp);
        displayTime = messageDate.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        });
      }
    }

    // Determine message style based on status
    let bubbleStyle = [
      styles.messageBubble,
      item.isMe ? styles.myBubble : styles.theirBubble,
    ];

    // Only add expired style if message is expired
    if (item.status === "expired") {
      bubbleStyle.push(styles.expiredBubble);
    }

    return (
      <TouchableOpacity
        activeOpacity={0.8}
        onLongPress={() => {
          setSelectedMessage(item);
          setDeleteModalVisible(true);
        }}
      >
        <View
          style={[
            styles.messageContainer,
            item.isMe ? styles.myMessage : styles.theirMessage,
          ]}
        >
          <View
            style={bubbleStyle}
            onLayout={() => {
              const markAsSeen = async () => {
                try {
                  // Only mark the message as seen if it's not already seen and not our own message
                  if (!item.seen && !item.isMe) {
                    const now = Date.now();

                    // Mark message as seen WITHOUT changing the visible status
                    setMessages((prevMessages) =>
                      prevMessages.map((msg) =>
                        msg.id === item.id
                          ? {
                              ...msg,
                              seen: true,
                              seenAt: now,
                            }
                          : msg
                      )
                    );

                    // Also save to storage to persist the seen status
                    const updatedMessages = messages.map((msg) =>
                      msg.id === item.id
                        ? {
                            ...msg,
                            seen: true,
                            seenAt: now,
                            time: msg.time,
                            timestamp: msg.timestamp,
                          }
                        : msg
                    );

                    saveLocalMessages(updatedMessages);

                    // Check if we've already marked this message as seen on the server
                    if (!seenMessagesRef.current.has(item.id)) {
                      // Add to set to prevent duplicate API calls
                      seenMessagesRef.current.add(item.id);

                      // Notify the server that the message was seen
                      try {
                        const authToken = await SecureStore.getItemAsync(
                          "token"
                        );
                        if (authToken) {
                          await axios.patch(
                            `${CONFIG.BACKEND_URL}/api/messages/${item.id}/read`,
                            {},
                            {
                              headers: { Authorization: `Bearer ${authToken}` },
                            }
                          );
                          console.log(
                            `(NOBRIDGE) LOG Marked message ${item.id} as seen on server`
                          );
                        }
                      } catch (error) {
                        // If it's a 404, just log it - the message was probably already deleted by the sender
                        if (error.response && error.response.status === 404) {
                          console.log(
                            `(NOBRIDGE) LOG Message ${item.id} already deleted from server`
                          );
                        } else {
                          console.error(
                            "(NOBRIDGE) ERROR Failed to notify server of seen message:",
                            error
                          );
                        }
                      }
                    } else {
                      console.log(
                        `(NOBRIDGE) LOG Message ${item.id} already marked as seen, skipping API call`
                      );
                    }
                  }
                } catch (error) {
                  console.error(
                    "(NOBRIDGE) ERROR Failed to mark message as seen:",
                    error
                  );
                }
              };
              markAsSeen();
            }}
          >
            {item.text ? (
              <Text
                style={[
                  styles.messageText,
                  item.status === "expired" ? styles.expiredText : null,
                ]}
              >
                {item.text}
              </Text>
            ) : item.imageData ? (
              <TouchableOpacity
                onPress={() => {
                  setSelectedImageUrl(item.imageData);
                  setIsImageModalVisible(true);
                }}
              >
                <Image
                  source={{ uri: item.imageData }}
                  style={[
                    styles.messageImage,
                    item.status === "expired" ? styles.expiredImage : null,
                  ]}
                  resizeMode="contain"
                />
              </TouchableOpacity>
            ) : (
              <Text style={styles.invalidMessageText}>[Message deleted]</Text>
            )}
            <View style={styles.messageFooter}>
              <Text style={styles.messageTime}>{displayTime}</Text>
              {item.isMe && (
                <>
                  <View style={styles.statusIcon}>
                    {item.status === "sent" && (
                      <Ionicons name="checkmark" size={14} color="#A9A9A9" />
                    )}
                    {item.status === "delivered" && (
                      <>
                        <Ionicons name="checkmark" size={14} color="#A9A9A9" />
                        <Ionicons
                          name="checkmark"
                          size={14}
                          color="#A9A9A9"
                          style={{ marginLeft: -5 }}
                        />
                      </>
                    )}
                    {item.status === "seen" && (
                      <>
                        <Ionicons name="checkmark" size={14} color="#FF3B30" />
                        <Ionicons
                          name="checkmark"
                          size={14}
                          color="#FF3B30"
                          style={{ marginLeft: -5 }}
                        />
                      </>
                    )}
                    {item.status === "expired" && (
                      <Ionicons name="time-outline" size={14} color="#FF3B30" />
                    )}
                  </View>
                  {/* Status text for sent messages only */}
                  <Text style={styles.statusText}>
                    {item.status || "unknown"}
                  </Text>
                </>
              )}
            </View>
          </View>
        </View>
      </TouchableOpacity>
    );
  };

  const renderInputContainer = () => (
    <View
      style={{
        ...styles.inputContainer,
        paddingBottom: getInputPadding(),
        marginBottom: getInputMargin(),
      }}
    >
      <TouchableOpacity
        style={styles.attachmentButton}
        onPress={() => setIsImageOptionsVisible(true)}
      >
        <Ionicons name="images-outline" size={24} color="white" />
      </TouchableOpacity>

      <TextInput
        style={styles.input}
        value={newMessage}
        onChangeText={setNewMessage}
        placeholder="Type a message..."
        placeholderTextColor="#888"
        multiline
      />

      <TouchableOpacity
        style={[
          styles.sendButton,
          newMessage.trim()
            ? styles.sendButtonActive
            : styles.sendButtonInactive,
        ]}
        onPress={handleSendMessage}
        disabled={!newMessage.trim()}
      >
        <Ionicons
          name="send"
          size={24}
          color={!newMessage.trim() ? "#666" : "white"}
        />
      </TouchableOpacity>

      <Modal
        isVisible={isImageOptionsVisible}
        onBackdropPress={() => setIsImageOptionsVisible(false)}
        style={styles.imageOptionsModal}
        backdropTransitionOutTiming={0}
        animationOutTiming={200}
      >
        <View style={styles.imageOptionsContainer}>
          <TouchableOpacity
            style={styles.imageOption}
            onPress={() => handleImageOption("library")}
          >
            <Ionicons name="images-outline" size={30} color="white" />
            <Text style={styles.imageOptionText}>Choose from Library</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.imageOption}
            onPress={() => handleImageOption("camera")}
          >
            <Ionicons name="camera-outline" size={30} color="white" />
            <Text style={styles.imageOptionText}>Take Photo</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.imageOption, styles.cancelOption]}
            onPress={() => setIsImageOptionsVisible(false)}
          >
            <Ionicons name="close-circle-outline" size={30} color="#ff6666" />
            <Text style={[styles.imageOptionText, { color: "#ff6666" }]}>
              Cancel
            </Text>
          </TouchableOpacity>
        </View>
      </Modal>
    </View>
  );

  const handleSendMessage = async () => {
    if (!newMessage.trim() || !isContactValid || !ratchet) return;

    try {
      const authToken = await SecureStore.getItemAsync("token");
      if (!authToken) throw new Error("Authentication token missing");

      // Store the original message text before sending
      const originalText = newMessage.trim();

      const encryptedMessage = await ratchet.encrypt(originalText);
      const tempId = uuidv4();
      const now = new Date();
      // Set a very far future expiration date (approx. 10 years) to effectively keep messages forever
      const expiresAt = new Date(
        Date.now() + 10 * 365 * 24 * 60 * 60 * 1000 // 10 years
      ).toISOString();

      // Format the current time properly
      const formattedTime = now.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });

      console.log(
        `(NOBRIDGE) LOG Formatted time for outgoing message: ${formattedTime}`
      );

      // Create the new message object with the original text
      const newMsg = {
        id: tempId,
        text: originalText, // Use the original text
        imageData: null,
        imagePath: null,
        time: formattedTime,
        isMe: true,
        timestamp: now.getTime(),
        sentAt: now.toISOString(),
        status: "sent", // Initial status is "sent"
      };

      console.log(`⭐️ SENDING NEW MESSAGE WITH STATUS: sent ⭐️`);

      // Add message to state immediately and force UI refresh for immediate visual feedback
      setMessages((prev) => {
        const updatedMessages = [...prev, newMsg];

        // Immediately save to local storage
        saveLocalMessages(updatedMessages);

        // Log the message we're adding
        console.log(
          `(NOBRIDGE) LOG Adding new message with ID ${newMsg.id} and status: ${newMsg.status}`
        );

        return updatedMessages;
      });

      // Force refresh to ensure status is visible
      setTimeout(() => {
        setMessages((currentMessages) => {
          console.log(
            `(NOBRIDGE) LOG Refreshing messages list to show sent status`
          );
          return [...currentMessages];
        });
      }, 100);

      setNewMessage("");

      const response = await axios.post(
        `${CONFIG.BACKEND_URL}/api/messages/send`,
        {
          receiver: contactData.name,
          ciphertext: encryptedMessage.ciphertext,
          nonce: encryptedMessage.nonce,
          headers: {
            dhPubKey: encryptedMessage.header.dhPubKey,
            messageIndex: encryptedMessage.header.messageIndex,
            prevChainLength: encryptedMessage.header.prevChainLength,
          },
          type: "text",
          expiresAt,
        },
        { headers: { Authorization: `Bearer ${authToken}` } }
      );

      // Format the server timestamp properly
      const serverTime = new Date(response.data.sentAt).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });

      console.log(
        `(NOBRIDGE) LOG Server timestamp formatted: ${serverTime} from ${response.data.sentAt}`
      );

      // Update the message with the server ID but keep the original text
      setMessages((prev) => {
        const updatedMessages = prev.map((msg) =>
          msg.id === tempId
            ? {
                id: response.data._id.toString(),
                text: originalText, // Keep the original text
                imageData: null,
                imagePath: null,
                time: serverTime,
                isMe: true,
                timestamp: new Date(response.data.sentAt).getTime(),
                sentAt: response.data.sentAt,
                status: "sent", // Ensure status is preserved
              }
            : msg
        );

        saveLocalMessages(updatedMessages);
        return updatedMessages;
      });

      await saveRatchetState();

      setTimeout(() => {
        flatListRef.current?.scrollToEnd({ animated: true });
      }, 100);
    } catch (error) {
      console.error(
        "(NOBRIDGE) ERROR ChatScreen - Error sending message:",
        String(error)
      );
      Alert.alert("Error", `Failed to send message: ${String(error)}`);
    }
  };

  useEffect(() => {
    const checkMessageDestruction = async () => {
      // Message destruction is now disabled - we're keeping messages forever
      console.log(
        "(NOBRIDGE) LOG Message destruction is disabled - keeping messages forever"
      );
      return;
    };

    // Run the disabled function
    checkMessageDestruction();

    // Return empty cleanup function
    return () => {};
  }, [messages.length, currentUsername, contactData?.name]);

  // Initialize enhanced randomness when component mounts
  useEffect(() => {
    const initRandom = async () => {
      try {
        await enhancedRandom.initialize();
        console.log("Enhanced randomness initialized in ChatScreen");
      } catch (error) {
        console.error("Error initializing enhanced randomness:", error);
      }
    };

    initRandom();
  }, []);

  // Component cleanup on unmount
  useEffect(() => {
    return () => {
      // Reset message destruction setup ref on unmount
      destructionSetupRef.current = false;

      // Clear any potential lingering timers or intervals
      // This helps prevent "Can't perform a React state update on an unmounted component" warnings
      const cleanup = () => {
        console.log("(NOBRIDGE) LOG Cleaning up ChatScreen resources");
      };

      cleanup();
    };
  }, []);

  // Message expiration check is now disabled - messages are kept forever
  const checkForExpiredMessages = async (loadedMessages) => {
    console.log(
      "(NOBRIDGE) LOG Message expiration check is disabled - keeping all messages"
    );
    return loadedMessages;
  };

  if (isLoading || !currentUserId || !ratchet) {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#252762" />
        <View style={styles.header}>
          <TouchableOpacity onPress={() => navigation.goBack()}>
            <Ionicons name="arrow-back-outline" size={24} color="white" />
          </TouchableOpacity>
          <View style={styles.headerCenter}>
            <Image
              source={require("../../assets/profile.png")}
              style={styles.headerProfileImage}
            />
            <Text style={styles.headerText}>{String(contactData.name)}</Text>
          </View>
          <View style={styles.width24} />
        </View>
        <View style={styles.loadingContainer}>
          <Text style={styles.loadingText}>Loading chat...</Text>
        </View>
      </SafeAreaView>
    );
  }

  if (!isContactValid) {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#252762" />
        <View style={styles.header}>
          <TouchableOpacity onPress={() => navigation.goBack()}>
            <Ionicons name="arrow-back-outline" size={24} color="white" />
          </TouchableOpacity>
          <View style={styles.headerCenter}>
            <Image
              source={require("../../assets/profile.png")}
              style={styles.headerProfileImage}
            />
            <Text style={styles.headerText}>{String(contactData.name)}</Text>
          </View>
          <View style={styles.width24} />
        </View>
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>You cannot chat with this user.</Text>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#252762" />
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back-outline" size={24} color="white" />
        </TouchableOpacity>
        <View style={styles.headerCenter}>
          <Image
            source={require("../../assets/profile.png")}
            style={styles.headerProfileImage}
          />
          <Text style={styles.headerText}>{String(contactData.name)}</Text>
        </View>
        <View style={styles.width24} />
      </View>
      <KeyboardAvoidingView
        behavior={Platform.OS === "ios" ? "padding" : undefined}
        style={styles.flex}
        keyboardVerticalOffset={getKeyboardOffset()}
      >
        <FlatList
          ref={flatListRef}
          data={messages}
          renderItem={renderMessage}
          keyExtractor={(item, index) =>
            item && item.id ? `msg-${item.id}-${index}` : `fallback-${index}`
          }
          contentContainerStyle={styles.messagesList}
          onContentSizeChange={() =>
            flatListRef.current?.scrollToEnd({ animated: true })
          }
        />
        {renderInputContainer()}
      </KeyboardAvoidingView>

      <Modal
        isVisible={isImageModalVisible}
        onBackdropPress={() => setIsImageModalVisible(false)}
        style={styles.modal}
      >
        <View style={styles.modalContent}>
          {selectedImageUrl && (
            <ImageViewer
              imageUrls={[{ url: selectedImageUrl }]}
              enableSwipeDown={true}
              onSwipeDown={() => setIsImageModalVisible(false)}
              renderIndicator={() => null}
            />
          )}
          <TouchableOpacity
            style={styles.modalCloseButton}
            onPress={() => setIsImageModalVisible(false)}
          >
            <Ionicons name="close" size={30} color="white" />
          </TouchableOpacity>
        </View>
      </Modal>

      <Modal
        isVisible={deleteModalVisible}
        onBackdropPress={() => setDeleteModalVisible(false)}
        style={styles.deleteModalContainer}
        backdropTransitionOutTiming={0}
        animationOutTiming={200}
      >
        <View style={styles.deleteModalContent}>
          <Text style={styles.deleteModalTitle}>Message Options</Text>

          <TouchableOpacity
            style={styles.deleteOption}
            onPress={() => handleDeleteMessage(selectedMessage?.id)}
          >
            <Ionicons name="trash-outline" size={22} color="#FF3B30" />
            <Text style={styles.deleteOptionText}>Delete Message</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.cancelOption}
            onPress={() => setDeleteModalVisible(false)}
          >
            <Text style={styles.cancelOptionText}>Cancel</Text>
          </TouchableOpacity>
        </View>
      </Modal>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#252762",
  },
  flex: {
    flex: 1,
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    padding: 15,
    backgroundColor: "#252762",
    borderBottomWidth: 1,
    borderBottomColor: "#fff",
    position: "relative",
  },
  headerCenter: {
    flexDirection: "row",
    alignItems: "center",
  },
  headerProfileImage: {
    width: 36,
    height: 36,
    borderRadius: 18,
    marginRight: 10,
    borderWidth: 2,
    borderColor: "#ffffff33",
  },
  headerText: {
    color: "white",
    fontSize: 18,
    fontWeight: "600",
    textShadowColor: "rgba(255, 255, 255, 0.3)",
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 10,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
  },
  loadingText: {
    color: "#888",
    fontSize: 16,
  },
  errorContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
  },
  errorText: {
    color: "#FF3B30",
    fontSize: 16,
  },
  messagesList: {
    padding: 10,
  },
  messageContainer: {
    flexDirection: "row",
    marginBottom: 10,
    alignItems: "flex-end",
  },
  myMessage: {
    justifyContent: "flex-end",
  },
  theirMessage: {
    justifyContent: "flex-start",
  },
  messageBubble: {
    maxWidth: "70%",
    padding: 12,
    borderRadius: 15,
  },
  myBubble: {
    backgroundColor: "#4A80F0",
    borderBottomRightRadius: 5,
    shadowColor: "#4A80F0",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 4,
  },
  theirBubble: {
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    borderBottomLeftRadius: 5,
  },
  expiredBubble: {
    backgroundColor: "rgba(128, 128, 128, 0.3)", // Gray out expired messages
    opacity: 0.8,
  },
  imageBubble: {
    padding: 5,
  },
  messageText: {
    color: "white",
    fontSize: 16,
  },
  messageImage: {
    width: 200,
    height: 200,
    borderRadius: 10,
  },
  messageFooter: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "flex-end",
    marginTop: 5,
  },
  messageTime: {
    color: "white",
    fontSize: 12,
    marginRight: 5,
  },
  statusIcon: {
    flexDirection: "row",
    marginLeft: 5,
  },
  statusText: {
    color: "#ffffff",
    fontSize: 12,
    marginLeft: 5,
    fontWeight: "bold",
    textTransform: "uppercase",
  },
  inputContainer: {
    flexDirection: "row",
    alignItems: "center",
    padding: 10,
    backgroundColor: "#252762",
    borderTopWidth: 1,
    borderTopColor: "#fff",
    minHeight: 60, // Ensure minimum height for the input container
  },
  input: {
    flex: 1,
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    color: "white",
    borderRadius: 20,
    paddingHorizontal: 15,
    paddingVertical: 10,
    maxHeight: 100,
    minHeight: 40, // Ensure minimum height for the input
  },
  sendButton: {
    marginLeft: 10,
    padding: 10,
    borderRadius: 20,
    minWidth: 44, // Ensure minimum width for the send button
    minHeight: 44, // Ensure minimum height for the send button
    justifyContent: "center",
    alignItems: "center",
  },
  sendButtonActive: {
    backgroundColor: "#4A80F0",
  },
  sendButtonInactive: {
    backgroundColor: "rgba(255, 255, 255, 0.1)",
  },
  attachmentButton: {
    marginRight: 10,
    padding: 10,
  },
  modal: {
    margin: 0,
  },
  modalContent: {
    flex: 1,
    backgroundColor: "black",
  },
  modalCloseButton: {
    position: "absolute",
    top: 40,
    right: 20,
    backgroundColor: "rgba(0, 0, 0, 0.5)",
    borderRadius: 20,
    padding: 10,
  },
  imageOptionsModal: {
    justifyContent: "flex-end",
    margin: 0,
  },
  imageOptionsContainer: {
    backgroundColor: "#252762",
    padding: 20,
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
  },
  imageOption: {
    flexDirection: "row",
    alignItems: "center",
    padding: 15,
    borderBottomWidth: 0.5,
    borderBottomColor: "rgba(255,255,255,0.1)",
  },
  imageOptionText: {
    color: "white",
    fontSize: 16,
    marginLeft: 15,
  },
  cancelOption: {
    borderTopWidth: 0.5,
    borderTopColor: "rgba(255,255,255,0.1)",
    marginTop: 10,
    paddingTop: 10,
  },
  width24: {
    width: 24,
  },
  deleteModalContainer: {
    justifyContent: "flex-end",
    margin: 0,
  },
  deleteModalContent: {
    backgroundColor: "#252762",
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    padding: 20,
    paddingBottom: 30,
  },
  deleteModalTitle: {
    color: "white",
    fontSize: 18,
    fontWeight: "600",
    marginBottom: 20,
    textAlign: "center",
  },
  deleteOption: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 15,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.1)",
  },
  deleteOptionText: {
    color: "#FF3B30",
    fontSize: 16,
    marginLeft: 15,
    fontWeight: "500",
  },
  cancelOption: {
    alignItems: "center",
    paddingVertical: 15,
    marginTop: 10,
  },
  cancelOptionText: {
    color: "#4A80F0",
    fontSize: 16,
    fontWeight: "600",
  },
  invalidMessageText: {
    fontStyle: "italic",
    color: "#888",
    fontSize: 14,
  },
  // New styles for message status
  expiredBubble: {
    backgroundColor: "rgba(128, 128, 128, 0.3)", // Gray out expired messages
    opacity: 0.8,
  },
  expiredText: {
    color: "#888", // Gray text for expired messages
    fontStyle: "italic",
  },
  expiredImage: {
    opacity: 0.5, // Fade out expired images
  },
  sentBubble: {
    backgroundColor: "#4A80F0",
  },
  deliveredBubble: {
    backgroundColor: "#A9A9A9",
  },
  seenBubble: {
    backgroundColor: "#FF3B30",
  },
});

export default ChatScreen;
