import React, { useState, useEffect, useCallback } from "react";
import {
  View,
  Text,
  StyleSheet,
  SafeAreaView,
  StatusBar,
  FlatList,
  TouchableOpacity,
  Alert,
  ActivityIndicator,
  RefreshControl,
  TextInput,
  Image,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import axios from "axios";
import * as SecureStore from "expo-secure-store";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import * as Crypto from "expo-crypto";
import Constants from "expo-constants";
import CONFIG from "../config/config";

// Utility function to validate Base64 strings
const isValidBase64 = (str) => {
  if (typeof str !== "string") return false;
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(str) && str.length % 4 === 0;
};

const ContactsScreen = ({ navigation, route }) => {
  const { token } = route.params || {};
  const [users, setUsers] = useState([]);
  const [pendingInvites, setPendingInvites] = useState([]);
  const [sentInvites, setSentInvites] = useState([]);
  const [contacts, setContacts] = useState([]);
  const [removedNotices, setRemovedNotices] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [username, setUsername] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");

  const axiosInstance = axios.create({
    timeout: 5000,
  });

  useEffect(() => {
    const initialize = async () => {
      if (token) {
        await SecureStore.setItemAsync("token", token);
      }

      let currentUsername = route.params?.username;
      if (!currentUsername) {
        currentUsername = await SecureStore.getItemAsync("username");
        console.log(
          `(NOBRIDGE) LOG Username fetched from SecureStore: ${currentUsername}`
        );
      }

      if (!currentUsername) {
        Alert.alert("Error", "Username not found. Please log in again.");
        navigation.reset({ index: 0, routes: [{ name: "Login" }] });
        return;
      }

      setUsername(currentUsername);

      const identityKeyPrivate = await SecureStore.getItemAsync(
        `${currentUsername}_identityKeyPrivate`
      );
      const signedPreKeyPrivate = await SecureStore.getItemAsync(
        `${currentUsername}_signedPreKeyPrivate`
      );
      const oneTimePreKeysPrivate = await SecureStore.getItemAsync(
        `${currentUsername}_oneTimePreKeysPrivate`
      );
      console.log(
        `(NOBRIDGE) LOG Checking SecureStore for ${currentUsername}:`
      );
      console.log(
        `(NOBRIDGE) LOG identityKeyPrivate: ${
          identityKeyPrivate ? "exists" : "not found"
        }`
      );
      console.log(
        `(NOBRIDGE) LOG signedPreKeyPrivate: ${
          signedPreKeyPrivate ? "exists" : "not found"
        }`
      );
      console.log(
        `(NOBRIDGE) LOG oneTimePreKeysPrivate: ${
          oneTimePreKeysPrivate ? "exists" : "not found"
        }`
      );

      if (
        !identityKeyPrivate ||
        !signedPreKeyPrivate ||
        !oneTimePreKeysPrivate
      ) {
        Alert.alert(
          "Error",
          "Required keys not found in SecureStore. Please register or log in again."
        );
        navigation.reset({ index: 0, routes: [{ name: "Login" }] });
        return;
      }

      fetchData(currentUsername);
    };
    initialize();
  }, [token, navigation]);

  const addLog = (message) => {
    console.log(`(NOBRIDGE) LOG ${message}`);
  };

  const initializeX3DHAsSender = async (
    senderUsername,
    recipientUsername,
    authToken
  ) => {
    try {
      addLog(
        `Starting X3DH initialization for sender: ${senderUsername} to ${recipientUsername}`
      );

      if (!senderUsername) {
        throw new Error("Sender username is undefined");
      }

      const identityKeyPrivateBase64 = await SecureStore.getItemAsync(
        `${senderUsername}_identityKeyPrivate`
      );
      if (!identityKeyPrivateBase64) {
        throw new Error("Sender identity key private not found");
      }

      if (!isValidBase64(identityKeyPrivateBase64)) {
        throw new Error("Invalid Base64 encoding for sender private key");
      }

      const identityKeyPrivate = naclUtil.decodeBase64(
        identityKeyPrivateBase64
      );
      if (identityKeyPrivate.length !== 32) {
        throw new Error("Invalid identity key private length");
      }

      addLog(`Fetching sender public keys for ${senderUsername}...`);
      const senderKeysResponse = await axiosInstance.get(
        `${CONFIG.BACKEND_URL}/api/users/keys/${senderUsername}`,
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      const senderKeys = senderKeysResponse.data;
      addLog(`Sender public keys: ${JSON.stringify(senderKeys)}`);

      if (!isValidBase64(senderKeys.identityKeyPublic)) {
        throw new Error(
          "Invalid Base64 encoding for sender identity key public"
        );
      }

      const senderIdentityKeyPublic = naclUtil.decodeBase64(
        senderKeys.identityKeyPublic
      );
      if (senderIdentityKeyPublic.length !== 32) {
        throw new Error("Invalid sender identity key public length");
      }

      addLog(`Fetching public keys for ${recipientUsername}...`);
      const receiverKeysResponse = await axiosInstance.get(
        `${CONFIG.BACKEND_URL}/api/users/keys/${recipientUsername}`,
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      const receiverKeys = receiverKeysResponse.data;
      addLog(`Receiver public keys: ${JSON.stringify(receiverKeys)}`);

      if (
        !isValidBase64(receiverKeys.identityKeyPublic) ||
        !isValidBase64(receiverKeys.signingKeyPublic) ||
        !isValidBase64(receiverKeys.signedPreKeyPublic) ||
        !isValidBase64(receiverKeys.signedPreKeySignature) ||
        (receiverKeys.oneTimePreKey &&
          !isValidBase64(receiverKeys.oneTimePreKey.publicKey))
      ) {
        throw new Error("Invalid Base64 encoding for receiver public keys");
      }

      const receiverIdentityKeyPublic = naclUtil.decodeBase64(
        receiverKeys.identityKeyPublic
      );
      const receiverSigningKeyPublic = naclUtil.decodeBase64(
        receiverKeys.signingKeyPublic
      );
      const receiverSignedPreKeyPublic = naclUtil.decodeBase64(
        receiverKeys.signedPreKeyPublic
      );
      const receiverSignedPreKeySignature = naclUtil.decodeBase64(
        receiverKeys.signedPreKeySignature
      );
      const receiverOneTimePreKeyPublic = receiverKeys.oneTimePreKey
        ? naclUtil.decodeBase64(receiverKeys.oneTimePreKey.publicKey)
        : null;

      if (
        receiverIdentityKeyPublic.length !== 32 ||
        receiverSigningKeyPublic.length !== 32 ||
        receiverSignedPreKeyPublic.length !== 32 ||
        (receiverOneTimePreKeyPublic &&
          receiverOneTimePreKeyPublic.length !== 32) ||
        receiverSignedPreKeySignature.length !== 64
      ) {
        throw new Error("Invalid receiver public key lengths");
      }

      const verifySignature = nacl.sign.detached.verify(
        receiverSignedPreKeyPublic,
        receiverSignedPreKeySignature,
        receiverSigningKeyPublic
      );
      if (!verifySignature) {
        throw new Error("Invalid signed pre-key signature for receiver");
      }
      addLog("Signed Pre-Key signature verified successfully");

      const ephemeralKeyPair = nacl.box.keyPair();
      const senderEphemeralKey = naclUtil.encodeBase64(
        ephemeralKeyPair.publicKey
      );
      addLog(`Sender ephemeral key: ${senderEphemeralKey}`);

      const usedOneTimePreKey = receiverKeys.oneTimePreKey;
      if (!usedOneTimePreKey) {
        throw new Error("No one-time pre-key available for receiver");
      }
      addLog(
        `Using one-time pre-key ID: ${usedOneTimePreKey.keyId}, Public Key: ${usedOneTimePreKey.publicKey}`
      );

      addLog("\n===== Posiljalac (Sender) izvršava X3DH =====");
      const dh1 = nacl.box.before(
        receiverSignedPreKeyPublic,
        identityKeyPrivate
      );
      const dh2 = nacl.box.before(
        receiverIdentityKeyPublic,
        ephemeralKeyPair.secretKey
      );
      const dh3 = nacl.box.before(
        receiverSignedPreKeyPublic,
        ephemeralKeyPair.secretKey
      );
      const dh4 = nacl.box.before(
        receiverOneTimePreKeyPublic,
        ephemeralKeyPair.secretKey
      );

      let ikm = new Uint8Array(
        dh1.length + dh2.length + dh3.length + dh4.length
      );
      ikm.set(dh1, 0);
      ikm.set(dh2, dh1.length);
      ikm.set(dh3, dh1.length + dh2.length);
      ikm.set(dh4, dh1.length + dh2.length + dh3.length);

      const senderSharedSecret = nacl.hash(ikm).slice(0, 32);
      const senderSharedSecretBase64 =
        naclUtil.encodeBase64(senderSharedSecret);
      addLog(`Sender shared secret: ${senderSharedSecretBase64}`);

      // Derive chain key for Double Ratchet
      const chainKey = nacl
        .hash(
          new Uint8Array([
            ...senderSharedSecret,
            ...naclUtil.decodeUTF8("chain-key"),
          ])
        )
        .slice(0, 32);
      const chainKeyBase64 = naclUtil.encodeBase64(chainKey);

      // Save the ratchet state
      const ratchetState = {
        rootKey: senderSharedSecretBase64,
        chainKey: chainKeyBase64,
        sendingChain: { prevChainLength: 0, messageIndex: 0 },
        receivingChain: { prevChainLength: 0, messageIndex: 0 },
        dhKeyPair: {
          publicKey: naclUtil.encodeBase64(ephemeralKeyPair.publicKey),
          privateKey: naclUtil.encodeBase64(ephemeralKeyPair.secretKey),
        },
        theirDhPubKey: usedOneTimePreKey
          ? naclUtil.encodeBase64(receiverOneTimePreKeyPublic)
          : naclUtil.encodeBase64(receiverSignedPreKeyPublic),
      };

      await SecureStore.setItemAsync(
        `ratchetState_${recipientUsername}`,
        JSON.stringify(ratchetState)
      );
      addLog(`Saved ratchet state for ${recipientUsername}`);

      const message = "pozdrav";
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      const messageBytes = naclUtil.decodeUTF8(message);
      const encryptedPayload = nacl.secretbox(
        messageBytes,
        nonce,
        senderSharedSecret
      );
      const encryptedPayloadBase64 = naclUtil.encodeBase64(encryptedPayload);
      const nonceBase64 = naclUtil.encodeBase64(nonce);
      addLog(`Nonce: ${nonceBase64}`);
      addLog(`Encrypted payload: ${encryptedPayloadBase64}`);

      return {
        senderIdentityKey: naclUtil.encodeBase64(senderIdentityKeyPublic),
        senderEphemeralKey,
        usedSignedPreKeyId: receiverKeys.signedPreKeyId,
        usedOneTimePreKeyId: usedOneTimePreKey.keyId,
        encryptedPayload: encryptedPayloadBase64,
        nonce: nonceBase64,
      };
    } catch (error) {
      addLog(`X3DH initialization failed (sender): ${error.message}`);
      throw error;
    }
  };

  const initializeX3DHAsReceiver = async (
    senderUsername,
    recipientUsername,
    authToken,
    senderIdentityKeyBase64,
    senderEphemeralKeyBase64,
    usedSignedPreKeyId,
    usedOneTimePreKeyId,
    encryptedPayloadBase64,
    nonceBase64,
    inviteId
  ) => {
    try {
      addLog(
        `Starting X3DH initialization for receiver: ${recipientUsername} from ${senderUsername}`
      );

      const identityKeyPrivateBase64 = await SecureStore.getItemAsync(
        `${recipientUsername}_identityKeyPrivate`
      );
      const signedPreKeyPrivateBase64 = await SecureStore.getItemAsync(
        `${recipientUsername}_signedPreKeyPrivate`
      );
      const oneTimePreKeysPrivateJSON = await SecureStore.getItemAsync(
        `${recipientUsername}_oneTimePreKeysPrivate`
      );

      if (
        !identityKeyPrivateBase64 ||
        !signedPreKeyPrivateBase64 ||
        !oneTimePreKeysPrivateJSON
      ) {
        throw new Error("Receiver private keys not found");
      }

      if (
        !isValidBase64(identityKeyPrivateBase64) ||
        !isValidBase64(signedPreKeyPrivateBase64)
      ) {
        throw new Error("Invalid Base64 encoding for receiver private keys");
      }

      const identityKeyPrivate = naclUtil.decodeBase64(
        identityKeyPrivateBase64
      );
      const signedPreKeyPrivate = naclUtil.decodeBase64(
        signedPreKeyPrivateBase64
      );
      const oneTimePreKeysPrivate = JSON.parse(oneTimePreKeysPrivateJSON);

      if (!Array.isArray(oneTimePreKeysPrivate)) {
        throw new Error("oneTimePreKeysPrivate is not an array");
      }

      if (
        identityKeyPrivate.length !== 32 ||
        signedPreKeyPrivate.length !== 32
      ) {
        throw new Error("Invalid receiver private key lengths");
      }

      const usedOneTimePreKey = oneTimePreKeysPrivate.find(
        (key) => key.keyId === usedOneTimePreKeyId
      );
      if (!usedOneTimePreKey) {
        throw new Error("Used one-time pre-key not found");
      }
      addLog(
        `Found used one-time pre-key ID: ${usedOneTimePreKey.keyId}, Private Key: ${usedOneTimePreKey.privateKey}`
      );

      if (!isValidBase64(usedOneTimePreKey.privateKey)) {
        throw new Error("Invalid Base64 encoding for one-time pre-key private");
      }

      const oneTimePreKeyPrivate = naclUtil.decodeBase64(
        usedOneTimePreKey.privateKey
      );
      if (oneTimePreKeyPrivate.length !== 32) {
        throw new Error("Invalid one-time pre-key private length");
      }

      addLog(`Fetching sender public keys for ${senderUsername}...`);
      const senderKeysResponse = await axiosInstance.get(
        `${CONFIG.BACKEND_URL}/api/users/keys/${senderUsername}`,
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      const senderKeys = senderKeysResponse.data;
      addLog(`Sender public keys: ${JSON.stringify(senderKeys)}`);

      if (
        !isValidBase64(senderIdentityKeyBase64) ||
        !isValidBase64(senderEphemeralKeyBase64) ||
        !isValidBase64(senderKeys.signingKeyPublic) ||
        !isValidBase64(senderKeys.signedPreKeyPublic) ||
        !isValidBase64(senderKeys.signedPreKeySignature)
      ) {
        throw new Error("Invalid Base64 encoding for sender public keys");
      }

      const senderIdentityKey = naclUtil.decodeBase64(senderIdentityKeyBase64);
      const senderEphemeralKey = naclUtil.decodeBase64(
        senderEphemeralKeyBase64
      );
      const senderSigningKeyPublic = naclUtil.decodeBase64(
        senderKeys.signingKeyPublic
      );
      const senderSignedPreKeyPublic = naclUtil.decodeBase64(
        senderKeys.signedPreKeyPublic
      );
      const senderSignedPreKeySignature = naclUtil.decodeBase64(
        senderKeys.signedPreKeySignature
      );

      if (
        senderIdentityKey.length !== 32 ||
        senderEphemeralKey.length !== 32 ||
        senderSigningKeyPublic.length !== 32 ||
        senderSignedPreKeyPublic.length !== 32 ||
        senderSignedPreKeySignature.length !== 64
      ) {
        throw new Error("Invalid sender public key lengths");
      }

      const verifySignature = nacl.sign.detached.verify(
        senderSignedPreKeyPublic,
        senderSignedPreKeySignature,
        senderSigningKeyPublic
      );
      if (!verifySignature) {
        throw new Error("Invalid signed pre-key signature for sender");
      }
      addLog("Sender Signed Pre-Key signature verified successfully");

      addLog("\n===== Primalac (Receiver) izvršava X3DH =====");
      const dh1Receiver = nacl.box.before(
        senderIdentityKey,
        signedPreKeyPrivate
      );
      const dh2Receiver = nacl.box.before(
        senderEphemeralKey,
        identityKeyPrivate
      );
      const dh3Receiver = nacl.box.before(
        senderEphemeralKey,
        signedPreKeyPrivate
      );
      const dh4Receiver = nacl.box.before(
        senderEphemeralKey,
        oneTimePreKeyPrivate
      );

      let ikmReceiver = new Uint8Array(
        dh1Receiver.length +
          dh2Receiver.length +
          dh3Receiver.length +
          dh4Receiver.length
      );
      ikmReceiver.set(dh1Receiver, 0);
      ikmReceiver.set(dh2Receiver, dh1Receiver.length);
      ikmReceiver.set(dh3Receiver, dh1Receiver.length + dh2Receiver.length);
      ikmReceiver.set(
        dh4Receiver,
        dh1Receiver.length + dh2Receiver.length + dh3Receiver.length
      );

      const receiverSharedSecret = nacl.hash(ikmReceiver).slice(0, 32);
      const receiverSharedSecretBase64 =
        naclUtil.encodeBase64(receiverSharedSecret);
      addLog(`Receiver shared secret: ${receiverSharedSecretBase64}`);

      // Derive chain key for Double Ratchet
      const chainKey = nacl
        .hash(
          new Uint8Array([
            ...receiverSharedSecret,
            ...naclUtil.decodeUTF8("chain-key"),
          ])
        )
        .slice(0, 32);
      const chainKeyBase64 = naclUtil.encodeBase64(chainKey);

      if (
        !isValidBase64(encryptedPayloadBase64) ||
        !isValidBase64(nonceBase64)
      ) {
        throw new Error(
          "Invalid Base64 encoding for encrypted payload or nonce"
        );
      }

      const encryptedPayload = naclUtil.decodeBase64(encryptedPayloadBase64);
      const nonce = naclUtil.decodeBase64(nonceBase64);
      const decryptedPayload = nacl.secretbox.open(
        encryptedPayload,
        nonce,
        receiverSharedSecret
      );
      if (!decryptedPayload) {
        throw new Error("Failed to decrypt initial message");
      }
      const decryptedMessage = naclUtil.encodeUTF8(decryptedPayload);
      addLog(`Decrypted initial message: ${decryptedMessage}`);

      // Generate receiver's DH key pair for Double Ratchet
      const ephemeralKeyPair = nacl.box.keyPair();
      const ratchetState = {
        rootKey: receiverSharedSecretBase64,
        chainKey: chainKeyBase64,
        sendingChain: { prevChainLength: 0, messageIndex: 0 },
        receivingChain: { prevChainLength: 0, messageIndex: 0 },
        dhKeyPair: {
          publicKey: naclUtil.encodeBase64(ephemeralKeyPair.publicKey),
          privateKey: naclUtil.encodeBase64(ephemeralKeyPair.secretKey),
        },
        theirDhPubKey: senderEphemeralKeyBase64,
      };

      await SecureStore.setItemAsync(
        `ratchetState_${senderUsername}`,
        JSON.stringify(ratchetState)
      );
      addLog(`Saved ratchet state for ${senderUsername}`);

      addLog("Confirming invite (receiver)...");
      const confirmResponse = await axiosInstance.patch(
        `${CONFIG.BACKEND_URL}/api/invites/${inviteId}/confirm`,
        { receiverDhPubKey: naclUtil.encodeBase64(ephemeralKeyPair.publicKey) },
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      addLog("Invite confirmed by receiver");

      return decryptedMessage;
    } catch (error) {
      addLog(`X3DH initialization failed (receiver): ${error.message}`);
      throw error;
    }
  };

  const fetchData = useCallback(
    async (currentUsername, search = "") => {
      setIsLoading(true);
      try {
        let authToken = token || (await SecureStore.getItemAsync("token"));
        if (!authToken) {
          throw new Error("Authentication token is missing");
        }

        let storedContacts = await SecureStore.getItemAsync(
          `${currentUsername}_contacts`
        );
        let contactsList = storedContacts ? JSON.parse(storedContacts) : [];

        const usersResponse = await axiosInstance.get(
          `${CONFIG.BACKEND_URL}/api/users${
            search ? `?search=${encodeURIComponent(search)}` : ""
          }`,
          {
            headers: { Authorization: `Bearer ${authToken}` },
          }
        );
        setUsers(
          usersResponse.data.filter((user) => user.username !== currentUsername)
        );

        const receivedInvitesResponse = await axiosInstance.get(
          `${CONFIG.BACKEND_URL}/api/invites/received`,
          { headers: { Authorization: `Bearer ${authToken}` } }
        );
        setPendingInvites(receivedInvitesResponse.data);

        const acceptedReceivedInvites = receivedInvitesResponse.data.filter(
          (invite) => invite.status === "accepted"
        );
        for (const invite of acceptedReceivedInvites) {
          if (!invite.confirmedByReceiver) {
            await axiosInstance.patch(
              `${CONFIG.BACKEND_URL}/api/invites/${invite._id}/confirm`,
              { receiverDhPubKey: null },
              { headers: { Authorization: `Bearer ${authToken}` } }
            );
            const senderUsername = invite.sender.username;
            if (!contactsList.includes(senderUsername)) {
              contactsList.push(senderUsername);
              await SecureStore.setItemAsync(
                `${currentUsername}_contacts`,
                JSON.stringify(contactsList)
              );
            }
          }
        }

        const sentInvitesResponse = await axiosInstance.get(
          `${CONFIG.BACKEND_URL}/api/invites/sent`,
          { headers: { Authorization: `Bearer ${authToken}` } }
        );
        setSentInvites(sentInvitesResponse.data);

        const acceptedSentInvites = sentInvitesResponse.data.filter(
          (invite) => invite.status === "accepted"
        );
        for (const invite of acceptedSentInvites) {
          if (!invite.confirmedBySender) {
            const confirmResponse = await axiosInstance.patch(
              `${CONFIG.BACKEND_URL}/api/invites/${invite._id}/confirm`,
              {},
              { headers: { Authorization: `Bearer ${authToken}` } }
            );
            const receiverUsername = invite.receiver.username;
            if (!contactsList.includes(receiverUsername)) {
              contactsList.push(receiverUsername);
              await SecureStore.setItemAsync(
                `${currentUsername}_contacts`,
                JSON.stringify(contactsList)
              );
            }
            const receiverDhPubKey = confirmResponse.data?.receiverDhPubKey;
            if (receiverDhPubKey) {
              if (!isValidBase64(receiverDhPubKey)) {
                throw new Error("Invalid Base64 encoding for receiverDhPubKey");
              }
              const receiverDhPubKeyBytes =
                naclUtil.decodeBase64(receiverDhPubKey);
              if (receiverDhPubKeyBytes.length !== 32) {
                throw new Error("Invalid receiverDhPubKey length");
              }
              const ratchetStateStr = await SecureStore.getItemAsync(
                `ratchetState_${receiverUsername}`
              );
              if (ratchetStateStr) {
                const ratchetState = JSON.parse(ratchetStateStr);
                ratchetState.theirDhPubKey = receiverDhPubKey;
                await SecureStore.setItemAsync(
                  `ratchetState_${receiverUsername}`,
                  JSON.stringify(ratchetState)
                );
                addLog(
                  `Updated ratchet state for ${receiverUsername} with theirDhPubKey: ${receiverDhPubKey}`
                );
              }
            }
          }
        }

        const removedInvites = receivedInvitesResponse.data.filter(
          (invite) => invite.status === "removed"
        );
        if (removedInvites.length > 0) {
          const removedUsernames = removedInvites.map(
            (invite) => invite.sender.username
          );
          contactsList = contactsList.filter(
            (username) => !removedUsernames.includes(username)
          );
          await SecureStore.setItemAsync(
            `${currentUsername}_contacts`,
            JSON.stringify(contactsList)
          );
        }

        const fetchedContacts = contactsList.map((username) => ({
          username,
          status: "accepted",
        }));
        setContacts(fetchedContacts);

        setRemovedNotices(removedInvites);
      } catch (error) {
        let errorMessage = error.response?.data?.error || "Failed to load data";
        if (error.response?.status === 401) {
          errorMessage = "Session expired. Please log in.";
          await SecureStore.deleteItemAsync("token");
          navigation.reset({ index: 0, routes: [{ name: "Login" }] });
        }
        Alert.alert("Error", errorMessage);
      } finally {
        setIsLoading(false);
        setRefreshing(false);
      }
    },
    [token, navigation]
  );

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await fetchData(username, searchQuery);
  }, [fetchData, username, searchQuery]);

  const handleSearch = useCallback(async () => {
    await fetchData(username, searchQuery);
  }, [fetchData, username, searchQuery]);

  // Add real-time filtering for users based on search query
  const filteredUsers = useCallback(
    (usersList) => {
      if (!searchQuery.trim()) return usersList;
      return usersList.filter((user) =>
        user.username.toLowerCase().includes(searchQuery.toLowerCase())
      );
    },
    [searchQuery]
  );

  const handleInvite = async (recipientUsername) => {
    try {
      let authToken = token || (await SecureStore.getItemAsync("token"));
      if (!authToken) {
        throw new Error("Authentication token is missing");
      }

      if (!username) {
        throw new Error("Username is not defined");
      }

      const {
        senderIdentityKey,
        senderEphemeralKey,
        usedSignedPreKeyId,
        usedOneTimePreKeyId,
        encryptedPayload,
        nonce,
      } = await initializeX3DHAsSender(username, recipientUsername, authToken);

      addLog("Sending invite to server...");
      const response = await axiosInstance.post(
        `${CONFIG.BACKEND_URL}/api/invites`,
        {
          receiverUsername: recipientUsername,
          senderIdentityKey,
          senderEphemeralKey,
          usedSignedPreKeyId,
          usedOneTimePreKeyId,
          encryptedPayload,
          nonce,
        },
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      addLog(`Invite sent successfully: ${JSON.stringify(response.data)}`);

      Alert.alert("Success", `Invite sent to @${recipientUsername}`);
      await fetchData(username, searchQuery);
    } catch (error) {
      let errorMessage = error.response?.data?.error || "Failed to send invite";
      if (error.response?.status === 401) {
        errorMessage = "Session expired. Please log in.";
        await SecureStore.deleteItemAsync("token");
        navigation.reset({ index: 0, routes: [{ name: "Login" }] });
      }
      Alert.alert("Error", errorMessage);
    }
  };

  const handleAcceptInvite = async (inviteId) => {
    try {
      let authToken = token || (await SecureStore.getItemAsync("token"));
      if (!authToken) {
        throw new Error("Authentication token is missing");
      }

      addLog("Accepting invite on server...");
      const acceptResponse = await axiosInstance.patch(
        `${CONFIG.BACKEND_URL}/api/invites/${inviteId}/accept`,
        {},
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      const {
        senderUsername,
        senderIdentityKey,
        senderEphemeralKey,
        usedSignedPreKeyId,
        usedOneTimePreKeyId,
        encryptedPayload,
        nonce,
      } = acceptResponse.data;
      addLog(`Invite accepted: ${JSON.stringify(acceptResponse.data)}`);

      if (
        !senderIdentityKey ||
        !senderEphemeralKey ||
        !encryptedPayload ||
        !nonce
      ) {
        throw new Error("Missing X3DH data in invite response");
      }

      const decryptedMessage = await initializeX3DHAsReceiver(
        senderUsername,
        username,
        authToken,
        senderIdentityKey,
        senderEphemeralKey,
        usedSignedPreKeyId,
        usedOneTimePreKeyId,
        encryptedPayload,
        nonce,
        inviteId
      );

      let storedContacts = await SecureStore.getItemAsync(
        `${username}_contacts`
      );
      let contactsList = storedContacts ? JSON.parse(storedContacts) : [];
      if (!contactsList.includes(senderUsername)) {
        contactsList.push(senderUsername);
        await SecureStore.setItemAsync(
          `${username}_contacts`,
          JSON.stringify(contactsList)
        );
      }

      Alert.alert(
        "Success",
        `Invite accepted. Initial message: ${decryptedMessage}`
      );
      await fetchData(username, searchQuery);
    } catch (error) {
      let errorMessage =
        error.response?.data?.error || "Failed to accept invite";
      if (error.response?.status === 401) {
        errorMessage = "Session expired. Please log in.";
        await SecureStore.deleteItemAsync("token");
        navigation.reset({ index: 0, routes: [{ name: "Login" }] });
      }
      Alert.alert("Error", errorMessage);
    }
  };

  const handleRejectInvite = async (inviteId) => {
    try {
      let authToken = token || (await SecureStore.getItemAsync("token"));
      if (!authToken) {
        throw new Error("Authentication token is missing");
      }

      addLog("Rejecting invite on server...");
      await axiosInstance.patch(
        `${CONFIG.BACKEND_URL}/api/invites/${inviteId}/reject`,
        {},
        { headers: { Authorization: `Bearer ${authToken}` } }
      );
      addLog(`Invite rejected: ${inviteId}`);

      Alert.alert("Success", "Invite rejected");
      await fetchData(username, searchQuery);
    } catch (error) {
      let errorMessage =
        error.response?.data?.error || "Failed to reject invite";
      if (error.response?.status === 401) {
        errorMessage = "Session expired. Please log in.";
        await SecureStore.deleteItemAsync("token");
        navigation.reset({ index: 0, routes: [{ name: "Login" }] });
      }
      Alert.alert("Error", errorMessage);
    }
  };

  const handleClearRemovedInvite = async (inviteId) => {
    try {
      let authToken = token || (await SecureStore.getItemAsync("token"));
      if (!authToken) {
        throw new Error("Authentication token is missing");
      }

      await axiosInstance.delete(
        `${CONFIG.BACKEND_URL}/api/invites/${inviteId}/clear`,
        { headers: { Authorization: `Bearer ${authToken}` } }
      );

      Alert.alert("Success", "Removed notice cleared");
      await fetchData(username, searchQuery);
    } catch (error) {
      let errorMessage =
        error.response?.data?.error || "Failed to clear removed notice";
      if (error.response?.status === 401) {
        errorMessage = "Session expired. Please log in.";
        await SecureStore.deleteItemAsync("token");
        navigation.reset({ index: 0, routes: [{ name: "Login" }] });
      }
      Alert.alert("Error", errorMessage);
    }
  };

  const handleRemoveContact = async (contactUsername) => {
    try {
      let authToken = token || (await SecureStore.getItemAsync("token"));
      if (!authToken) {
        throw new Error("Authentication token is missing");
      }

      await axiosInstance.patch(
        `${CONFIG.BACKEND_URL}/api/invites/remove-contact`,
        { contactUsername },
        { headers: { Authorization: `Bearer ${authToken}` } }
      );

      await SecureStore.deleteItemAsync(
        `${username}_contact_${contactUsername}`
      );
      let storedContacts = await SecureStore.getItemAsync(
        `${username}_contacts`
      );
      let contactsList = storedContacts ? JSON.parse(storedContacts) : [];
      contactsList = contactsList.filter(
        (contact) => contact !== contactUsername
      );
      await SecureStore.setItemAsync(
        `${username}_contacts`,
        JSON.stringify(contactsList)
      );
      addLog(`Removed contact ${contactUsername} from SecureStore`);

      Alert.alert("Success", `Contact @${contactUsername} removed`);
      await fetchData(username, searchQuery);
    } catch (error) {
      let errorMessage =
        error.response?.data?.error || "Failed to remove contact";
      if (error.response?.status === 401) {
        errorMessage = "Session expired. Please log in.";
        await SecureStore.deleteItemAsync("token");
        navigation.reset({ index: 0, routes: [{ name: "Login" }] });
      }
      Alert.alert("Error", errorMessage);
    }
  };

  const handleOpenChat = async (contactUsername) => {
    try {
      const userId = await SecureStore.getItemAsync("userId");
      navigation.navigate("Chat", {
        contact: { username: contactUsername },
        userId,
        username,
      });
    } catch (error) {
      Alert.alert("Error", "Failed to open chat");
    }
  };

  const getInviteStatus = (userUsername) => {
    const isContact = contacts.some(
      (contact) => contact.username === userUsername
    );
    if (isContact) {
      return { status: "contact" };
    }

    const sent = sentInvites.find(
      (invite) =>
        invite.receiver.username === userUsername && invite.status === "pending"
    );
    if (sent) {
      return { status: "sent", inviteId: sent._id };
    }

    const received = pendingInvites.find(
      (invite) =>
        invite.sender.username === userUsername && invite.status === "pending"
    );
    if (received) {
      return { status: "pending", inviteId: received._id };
    }

    const removedNotice = removedNotices.find(
      (notice) => notice.sender.username === userUsername
    );
    if (removedNotice) {
      return { status: "removed", inviteId: removedNotice._id };
    }

    return { status: "none" };
  };

  const renderItem = ({ item }) => {
    const { status, inviteId } = getInviteStatus(item.username);

    return (
      <TouchableOpacity
        style={styles.contactItem}
        onPress={() => {
          if (status === "contact") {
            handleOpenChat(item.username);
          }
        }}
        disabled={status !== "contact"}
        activeOpacity={0.8}
      >
        <View style={styles.contactLeft}>
          <Image
            source={require("../../assets/profile.png")}
            style={styles.contactProfileImage}
          />
          <Text style={styles.contactUsername}>@{item.username}</Text>
        </View>
        <View style={styles.contactRight}>
          {status === "none" && (
            <TouchableOpacity
              style={styles.inviteButton}
              onPress={() => handleInvite(item.username)}
              activeOpacity={0.7}
            >
              <Ionicons name="person-add-outline" size={18} color="white" />
              <Text style={styles.buttonText}>Invite</Text>
            </TouchableOpacity>
          )}
          {status === "sent" && (
            <View style={styles.statusContainer}>
              <Ionicons
                name="hourglass-outline"
                size={16}
                color="#888"
                style={styles.statusIcon}
              />
              <Text style={styles.inviteStatus}>Waiting...</Text>
            </View>
          )}
          {status === "pending" && (
            <View style={styles.pendingActions}>
              <TouchableOpacity
                style={styles.acceptButton}
                onPress={() => handleAcceptInvite(inviteId)}
                activeOpacity={0.7}
              >
                <Ionicons name="checkmark-outline" size={18} color="white" />
                <Text style={styles.buttonText}>Accept</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.rejectButton}
                onPress={() => handleRejectInvite(inviteId)}
                activeOpacity={0.7}
              >
                <Ionicons name="close-outline" size={18} color="white" />
                <Text style={styles.buttonText}>Reject</Text>
              </TouchableOpacity>
            </View>
          )}
          {status === "contact" && (
            <View style={styles.contactActions}>
              <TouchableOpacity
                onPress={() => handleOpenChat(item.username)}
                style={styles.actionIcon}
                activeOpacity={0.7}
              >
                <Ionicons name="chatbubble-outline" size={24} color="#4A80F0" />
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.removeButton}
                onPress={() => handleRemoveContact(item.username)}
                activeOpacity={0.7}
              >
                <Ionicons
                  name="person-remove-outline"
                  size={18}
                  color="white"
                />
                <Text style={styles.buttonText}>Remove</Text>
              </TouchableOpacity>
            </View>
          )}
          {status === "removed" && (
            <View style={styles.contactActions}>
              <View style={styles.removedContainer}>
                <Ionicons
                  name="warning-outline"
                  size={16}
                  color="#FF5555"
                  style={styles.statusIcon}
                />
                <Text style={styles.removedText}>Removed</Text>
              </View>
              <TouchableOpacity
                style={styles.clearButton}
                onPress={() => handleClearRemovedInvite(inviteId)}
                activeOpacity={0.7}
              >
                <Ionicons name="close-outline" size={18} color="white" />
                <Text style={styles.buttonText}>Clear</Text>
              </TouchableOpacity>
            </View>
          )}
        </View>
      </TouchableOpacity>
    );
  };

  const myContacts = filteredUsers(
    users.filter((user) =>
      contacts.some((contact) => contact.username === user.username)
    )
  );
  const otherUsers = filteredUsers(
    users.filter(
      (user) => !contacts.some((contact) => contact.username === user.username)
    )
  );

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#252762" />
      <View style={styles.header}>
        <View style={styles.headerContent}>
          <Ionicons name="people-outline" size={28} color="white" />
          <Text style={styles.headerTitle}>
            Contacts (@{username || "Loading..."})
          </Text>
        </View>
      </View>
      <View style={styles.searchContainer}>
        <Ionicons
          name="search-outline"
          size={20}
          color="#888"
          style={styles.searchIcon}
        />
        <TextInput
          style={styles.searchInput}
          placeholder="Search users..."
          placeholderTextColor="#888"
          value={searchQuery}
          onChangeText={(text) => {
            setSearchQuery(text);
            // Remove onSubmitEditing since we're filtering in real-time
          }}
        />
        {searchQuery.length > 0 && (
          <TouchableOpacity
            onPress={() => {
              setSearchQuery("");
            }}
            style={styles.clearSearchButton}
          >
            <Ionicons name="close-circle" size={20} color="#888" />
          </TouchableOpacity>
        )}
      </View>
      {isLoading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#4A80F0" />
          <Text style={styles.loadingText}>Loading...</Text>
        </View>
      ) : (
        <>
          {myContacts.length > 0 && (
            <>
              <Text style={styles.sectionHeader}>My Contacts</Text>
              <FlatList
                data={myContacts}
                keyExtractor={(item) => `contact-${item._id || item.username}`}
                renderItem={renderItem}
                contentContainerStyle={styles.listContent}
                scrollEnabled={false}
              />
            </>
          )}
          {(otherUsers.length > 0 || searchQuery) && (
            <>
              <Text style={styles.sectionHeader}>Other Users</Text>
              <FlatList
                data={otherUsers}
                keyExtractor={(item) => `user-${item._id || item.username}`}
                renderItem={renderItem}
                contentContainerStyle={styles.listContent}
                ListEmptyComponent={
                  searchQuery && (
                    <View style={styles.emptyContainer}>
                      <Text style={styles.emptyText}>
                        No users found for "{searchQuery}"
                      </Text>
                    </View>
                  )
                }
                refreshControl={
                  <RefreshControl
                    refreshing={refreshing}
                    onRefresh={onRefresh}
                    tintColor="#4A80F0"
                  />
                }
              />
            </>
          )}
          {myContacts.length === 0 &&
            otherUsers.length === 0 &&
            !searchQuery && (
              <View style={styles.emptyContainer}>
                <Ionicons name="sad-outline" size={40} color="#888" />
                <Text style={styles.emptyText}>No users found</Text>
              </View>
            )}
        </>
      )}
    </SafeAreaView>
  );
};

// Disable swipe gestures for ContactsScreen
ContactsScreen.navigationOptions = {
  gestureEnabled: false,
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#252762",
  },
  header: {
    backgroundColor: "#252762",
    paddingVertical: 12,
    paddingHorizontal: 15,
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
    marginLeft: 10,
    textShadowColor: "rgba(255, 255, 255, 0.3)",
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 10,
  },
  searchContainer: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "rgba(255, 255, 255, 0.1)",
    margin: 10,
    paddingHorizontal: 15,
    borderRadius: 12,
    height: 45,
  },
  searchIcon: {
    marginRight: 10,
  },
  searchInput: {
    flex: 1,
    color: "white",
    fontSize: 16,
  },
  clearSearchButton: {
    padding: 5,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
  },
  loadingText: {
    color: "#888",
    marginTop: 10,
    fontSize: 16,
  },
  sectionHeader: {
    color: "white",
    fontSize: 14,
    fontWeight: "600",
    marginLeft: 20,
    marginTop: 20,
    marginBottom: 10,
  },
  listContent: {
    paddingHorizontal: 10,
  },
  contactItem: {
    flexDirection: "row",
    alignItems: "center",
    padding: 12,
    backgroundColor: "rgba(255, 255, 255, 0.05)",
    borderRadius: 12,
    marginVertical: 5,
  },
  contactLeft: {
    flexDirection: "row",
    alignItems: "center",
    flex: 1,
  },
  contactAvatar: {
    width: 50,
    height: 50,
    borderRadius: 25,
    marginRight: 12,
    borderWidth: 2,
    borderColor: "#ffffff33",
  },
  contactInfo: {
    flex: 1,
  },
  contactName: {
    color: "white",
    fontSize: 16,
    fontWeight: "600",
  },
  contactUsername: {
    color: "#888",
    fontSize: 14,
  },
  addButton: {
    backgroundColor: "#4A80F0",
    paddingHorizontal: 20,
    paddingVertical: 8,
    borderRadius: 8,
    shadowColor: "#4A80F0",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 4,
  },
  addButtonText: {
    color: "white",
    fontSize: 14,
    fontWeight: "600",
  },
  removeButton: {
    backgroundColor: "#FF3B30",
    paddingHorizontal: 20,
    paddingVertical: 8,
    borderRadius: 8,
    shadowColor: "#FF3B30",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 4,
  },
  removeButtonText: {
    color: "white",
    fontSize: 14,
    fontWeight: "600",
  },
  emptyContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    paddingVertical: 50,
  },
  emptyText: {
    color: "#888",
    fontSize: 16,
    marginTop: 10,
    textAlign: "center",
  },
  contactRight: {
    flexDirection: "row",
    alignItems: "center",
  },
  statusContainer: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 20,
    backgroundColor: "#252525",
  },
  statusIcon: {
    marginRight: 6,
  },
  inviteStatus: {
    color: "#888",
    fontSize: 14,
    fontWeight: "500",
  },
  inviteButton: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#4A80F0",
    borderRadius: 20,
    paddingHorizontal: 14,
    paddingVertical: 8,
    shadowColor: "#4A80F0",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.4,
    shadowRadius: 3,
    elevation: 3,
  },
  acceptButton: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#4A80F0",
    borderRadius: 20,
    paddingHorizontal: 14,
    paddingVertical: 8,
    shadowColor: "#4A80F0",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.4,
    shadowRadius: 3,
    elevation: 3,
  },
  rejectButton: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#FF5555",
    borderRadius: 20,
    paddingHorizontal: 14,
    paddingVertical: 8,
    marginLeft: 10,
    shadowColor: "#FF5555",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.4,
    shadowRadius: 3,
    elevation: 3,
  },
  removeButton: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#FF5555",
    borderRadius: 20,
    paddingHorizontal: 14,
    paddingVertical: 8,
    marginLeft: 10,
    shadowColor: "#FF5555",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.4,
    shadowRadius: 3,
    elevation: 3,
  },
  clearButton: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#FF5555",
    borderRadius: 20,
    paddingHorizontal: 14,
    paddingVertical: 8,
    marginLeft: 10,
    shadowColor: "#FF5555",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.4,
    shadowRadius: 3,
    elevation: 3,
  },
  buttonText: {
    color: "white",
    fontSize: 14,
    fontWeight: "600",
    marginLeft: 6,
  },
  contactActions: {
    flexDirection: "row",
    alignItems: "center",
  },
  actionIcon: {
    padding: 8,
  },
  removedContainer: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#2A1A1A",
    borderRadius: 20,
    paddingHorizontal: 10,
    paddingVertical: 6,
  },
  removedText: {
    color: "#FF5555",
    fontSize: 14,
    fontWeight: "500",
    marginLeft: 6,
  },
  pendingActions: {
    flexDirection: "row",
    alignItems: "center",
  },
  contactProfileImage: {
    width: 36,
    height: 36,
    borderRadius: 18,
    marginRight: 12,
  },
});

export default ContactsScreen;
