import React, {
  useState,
  useMemo,
  useCallback,
  useEffect,
  useRef,
} from "react";
import {
  View,
  Text,
  Image,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  StatusBar,
  KeyboardAvoidingView,
  Platform,
  BackHandler,
  Animated,
  Alert,
  ActivityIndicator,
} from "react-native";
import { useNavigation } from "@react-navigation/native";
import { Ionicons } from "@expo/vector-icons";
import * as Font from "expo-font";
import * as SecureStore from "expo-secure-store";
import axios from "axios";
import io from "socket.io-client";
import CONFIG from "../config/config";
import { Swipeable } from "react-native-gesture-handler";

// Create axios instance with retry logic
const axiosInstance = axios.create();
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { config, response } = error;
    const status = response?.status;

    // Don't retry if we don't have a config or if there's no status code
    if (!config || !status) return Promise.reject(error);

    // Only retry for specific status codes and if not already retried too many times
    if (
      (status === 429 || status >= 500) &&
      (!config._retryCount || config._retryCount < 3)
    ) {
      config._retryCount = config._retryCount || 0;
      config._retryCount += 1;

      // Exponential backoff delay
      const delay = Math.min(2 ** config._retryCount * 1000, 10000);
      console.log(
        `(NOBRIDGE) LOG Retrying request after ${delay}ms (attempt ${config._retryCount})`
      );

      return new Promise((resolve) => {
        setTimeout(() => resolve(axiosInstance(config)), delay);
      });
    }

    return Promise.reject(error);
  }
);

const MainScreen = ({ route }) => {
  const navigation = useNavigation();
  const { token, userId, username } = route.params || {};
  const [fontLoaded, setFontLoaded] = useState(false);
  const [fadeAnims, setFadeAnims] = useState([]);
  const [contacts, setContacts] = useState([]);
  const socketRef = useRef(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Format timestamp based on date
  const formatMessageTime = (timestamp) => {
    if (!timestamp || isNaN(new Date(timestamp).getTime())) {
      console.warn("(NOBRIDGE) LOG Invalid timestamp:", timestamp);
      return "";
    }
    const messageDate = new Date(timestamp);
    const now = new Date();
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);
    const oneWeekAgo = new Date(now);
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    if (messageDate.toDateString() === now.toDateString()) {
      return messageDate.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
    } else if (messageDate.toDateString() === yesterday.toDateString()) {
      return "Yesterday";
    } else if (messageDate > oneWeekAgo) {
      const days = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
      ];
      return days[messageDate.getDay()];
    } else {
      const day = messageDate.getDate().toString().padStart(2, "0");
      const month = (messageDate.getMonth() + 1).toString().padStart(2, "0");
      const year = messageDate.getFullYear();
      return `${day}.${month}.${year}`;
    }
  };

  // Process new messages from server
  const processNewServerMessage = async (message, authToken) => {
    try {
      const contactName = message.sender.username;

      // Store message in secure storage
      const messagesKey = `messages_${username}_${contactName}`;
      const storedMessagesStr = await SecureStore.getItemAsync(messagesKey);
      let storedMessages = storedMessagesStr
        ? JSON.parse(storedMessagesStr)
        : [];

      // Check if we already have this message
      const existingMsgIndex = storedMessages.findIndex(
        (msg) => msg.id === message._id
      );

      if (existingMsgIndex === -1) {
        // Format time properly from the server timestamp
        const messageDate = new Date(message.sentAt);
        const formattedTime = messageDate.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        });

        console.log(
          `(NOBRIDGE) LOG Formatted time for message ${message._id}: ${formattedTime} from ${message.sentAt}`
        );

        // Store complete message in secure storage with ALL its properties
        // CRITICAL: Store the complete headers object including dhPubKey for decryption
        const newMessage = {
          id: message._id,
          text: message.text || "",
          ciphertext: message.ciphertext,
          nonce: message.nonce,
          headers: message.headers, // Store complete headers object
          type: message.type || "text",
          sender: { username: message.sender.username },
          receiver: { username: message.receiver.username },
          sentAt: message.sentAt,
          time: formattedTime,
          timestamp: new Date(message.sentAt).getTime(),
          isMe: false, // Important: Add isMe property for incoming messages
          status: "delivered",
        };

        storedMessages.push(newMessage);
        await SecureStore.setItemAsync(
          messagesKey,
          JSON.stringify(storedMessages)
        );
        console.log(
          `(NOBRIDGE) LOG Stored complete message ${message._id} in secure storage`
        );

        // Mark as delivered on server (this will clear sensitive data)
        try {
          await axiosInstance.patch(
            `${CONFIG.BACKEND_URL}/api/messages/${message._id}/delivered`,
            {},
            { headers: { Authorization: `Bearer ${authToken}` } }
          );
          console.log(
            `(NOBRIDGE) LOG Marked message ${message._id} as delivered`
          );

          return newMessage;
        } catch (err) {
          console.error(
            `(NOBRIDGE) ERROR Failed to mark message as delivered: ${err.message}`
          );
        }
      }
      return null;
    } catch (error) {
      console.error(
        `(NOBRIDGE) ERROR Failed to process message: ${error.message}`
      );
      return null;
    }
  };

  // Fetch messages and update contacts - only runs on manual refresh
  const fetchMessagesAndUpdateContacts = useCallback(async () => {
    console.log("(NOBRIDGE) LOG Manual refresh triggered");

    // Set loading state for manual refresh
    setIsRefreshing(true);

    try {
      const authToken = await SecureStore.getItemAsync("token");
      if (!authToken) {
        throw new Error("Authentication token missing");
      }

      const storedContacts = await SecureStore.getItemAsync(
        `${username}_contacts`
      );
      let contactsList = storedContacts ? JSON.parse(storedContacts) : [];
      if (!Array.isArray(contactsList)) {
        console.warn(
          "(NOBRIDGE) WARN Contacts list is not an array:",
          storedContacts
        );
        contactsList = [];
      }
      contactsList = contactsList.filter(
        (contact) => typeof contact === "string" && contact.trim() !== ""
      );
      console.log("(NOBRIDGE) LOG Contacts list:", contactsList);

      if (contactsList.length === 0) {
        console.log("(NOBRIDGE) LOG No contacts found");
        setContacts([]);
        setFadeAnims([]);
        setIsRefreshing(false);
        return;
      }

      let serverMessages = [];
      try {
        const response = await axiosInstance.get(
          `${CONFIG.BACKEND_URL}/api/messages`,
          {
            headers: { Authorization: `Bearer ${authToken}` },
            timeout: 10000,
          }
        );
        serverMessages = Array.isArray(response.data) ? response.data : [];
        console.log(
          `(NOBRIDGE) LOG Fetched ${serverMessages.length} messages from server`
        );

        // Process ALL new messages for all contacts
        let newMessagesAdded = false;

        // Go through each contact to check and process messages
        for (const contactName of contactsList) {
          // Filter messages for this contact
          const contactMessages = serverMessages.filter(
            (msg) =>
              (msg.sender.username === contactName &&
                msg.receiver.username === username) ||
              (msg.sender.username === username &&
                msg.receiver.username === contactName)
          );

          if (contactMessages.length === 0) {
            continue;
          }

          console.log(
            `(NOBRIDGE) LOG Processing ${contactMessages.length} messages for contact ${contactName}`
          );

          // Get existing messages for this contact
          const storedMessagesKey = `messages_${username}_${contactName}`;
          const storedMessagesStr = await SecureStore.getItemAsync(
            storedMessagesKey
          );
          let storedMessages = storedMessagesStr
            ? JSON.parse(storedMessagesStr)
            : [];

          // Process each message
          for (const message of contactMessages) {
            // Only process new messages with "sent" status that we don't already have
            if (
              message.status === "sent" &&
              !storedMessages.some((msg) => msg.id === message._id)
            ) {
              const newMessage = await processNewServerMessage(
                message,
                authToken
              );
              if (newMessage) {
                newMessagesAdded = true;
                // Update UI with the new message
                await handleNewMessage(newMessage);
              }
            }
          }
        }

        if (newMessagesAdded) {
          console.log("(NOBRIDGE) LOG Added new messages during refresh");
        } else {
          console.log("(NOBRIDGE) LOG No new messages to add during refresh");
        }
      } catch (error) {
        console.error(
          "(NOBRIDGE) ERROR Error fetching server messages:",
          error.message
        );
        // Continue even if server fetch fails - we can still show local messages
      }

      // Always update contacts from local storage at the end
      await updateContactsFromLocalStorage();

      // Force refresh of UI
      setContacts((oldContacts) => [...oldContacts]);
    } catch (error) {
      console.error("(NOBRIDGE) ERROR Error loading resources:", error.message);
      if (error.response?.status === 401) {
        navigation.reset({ index: 0, routes: [{ name: "Login" }] });
      }
    } finally {
      setIsRefreshing(false);
      console.log("(NOBRIDGE) LOG Manual refresh completed");
    }
  }, [
    username,
    navigation,
    formatMessageTime,
    handleNewMessage,
    processNewServerMessage,
    updateContactsFromLocalStorage,
  ]);

  // Add periodic update function
  const periodicMessageCheck = useCallback(async () => {
    console.log("(NOBRIDGE) LOG Running periodic message check");
    if (socketRef.current?.connected) {
      try {
        const authToken = await SecureStore.getItemAsync("token");
        if (!authToken) {
          throw new Error("Authentication token missing");
        }

        // Fetch ALL messages from server, not just ones with "sent" status
        const response = await axiosInstance.get(
          `${CONFIG.BACKEND_URL}/api/messages`,
          {
            headers: { Authorization: `Bearer ${authToken}` },
            timeout: 5000, // shorter timeout for periodic check
          }
        );

        const serverMessages = Array.isArray(response.data)
          ? response.data
          : [];
        console.log(
          `(NOBRIDGE) LOG Periodic check: fetched ${serverMessages.length} messages from server`
        );

        let messageProcessed = false;

        // Process ANY message from the server that we don't already have
        for (const message of serverMessages) {
          // Get contacts list
          const storedContacts = await SecureStore.getItemAsync(
            `${username}_contacts`
          );
          const contactsList = storedContacts ? JSON.parse(storedContacts) : [];

          // Only process messages from contacts
          const contactName = message.sender.username;
          if (!contactsList.includes(contactName)) {
            continue;
          }

          // Check if we already have this message
          const messagesKey = `messages_${username}_${contactName}`;
          const storedMessagesStr = await SecureStore.getItemAsync(messagesKey);
          let storedMessages = storedMessagesStr
            ? JSON.parse(storedMessagesStr)
            : [];

          const existingMsg = storedMessages.find(
            (msg) => msg.id === message._id
          );

          // If we don't have this message, process it
          if (!existingMsg) {
            const newMessage = await processNewServerMessage(
              message,
              authToken
            );
            if (newMessage) {
              await handleNewMessage(newMessage);
              messageProcessed = true;
            }
          }
        }

        // Always update contacts from local storage to ensure counts are accurate
        await updateContactsFromLocalStorage();

        // Force UI refresh if any message was processed
        if (messageProcessed) {
          console.log(
            "(NOBRIDGE) LOG New messages processed, forcing UI refresh"
          );
          setContacts((oldContacts) => [...oldContacts]);
        }
      } catch (error) {
        console.error("(NOBRIDGE) ERROR In periodic check:", error.message);
      }
    }
  }, [
    username,
    handleNewMessage,
    processNewServerMessage,
    updateContactsFromLocalStorage,
  ]);

  // Helper function to update contacts list from local storage
  const updateContactsFromLocalStorage = async () => {
    try {
      const storedContacts = await SecureStore.getItemAsync(
        `${username}_contacts`
      );
      let contactsList = storedContacts ? JSON.parse(storedContacts) : [];
      if (!Array.isArray(contactsList)) {
        console.warn(
          "(NOBRIDGE) WARN Contacts list is not an array:",
          storedContacts
        );
        contactsList = [];
      }
      contactsList = contactsList.filter(
        (contact) => typeof contact === "string" && contact.trim() !== ""
      );

      if (contactsList.length === 0) {
        console.log("(NOBRIDGE) LOG No contacts found during update");
        return;
      }

      const contactsData = [];

      for (const contactName of contactsList) {
        const storedMessagesKey = `messages_${username}_${contactName}`;
        const storedMessages = await SecureStore.getItemAsync(
          storedMessagesKey
        );
        let localMessages = storedMessages ? JSON.parse(storedMessages) : [];
        localMessages = Array.isArray(localMessages) ? localMessages : [];

        // Filter valid messages
        localMessages = localMessages.filter(
          (msg) =>
            msg.id &&
            (msg.sentAt || msg.timestamp) &&
            ((msg.sender?.username && msg.receiver?.username) ||
              msg.isMe !== undefined) &&
            (msg.text !== undefined || msg.imagePath)
        );

        // Only add to contacts list if there are messages
        if (localMessages.length > 0) {
          // Sort messages by timestamp (newest first)
          localMessages.sort((a, b) => {
            const timeA = a.timestamp || new Date(a.sentAt).getTime();
            const timeB = b.timestamp || new Date(b.sentAt).getTime();
            return timeB - timeA;
          });

          // Get the most recent message
          const latestMsg = localMessages[0];
          const latestMessageDate =
            latestMsg.timestamp || new Date(latestMsg.sentAt).getTime();
          const time = formatMessageTime(
            latestMsg.sentAt || new Date(latestMessageDate)
          );

          // Count unread messages
          const unread = localMessages.filter(
            (msg) =>
              (msg.receiver?.username === username ||
                (!msg.isMe && msg.sender?.username === contactName)) &&
              msg.status !== "seen"
          ).length;

          console.log(
            `(NOBRIDGE) LOG Contact ${contactName} has ${unread} unread messages`
          );

          contactsData.push({
            id: contactName,
            name: contactName,
            lastMessage: "Message",
            time,
            unread,
            avatar: require("../../assets/profile.png"),
            latestMessageDate,
          });
        }
      }

      // Sort contacts by message time (newest first)
      contactsData.sort((a, b) => b.latestMessageDate - a.latestMessageDate);

      // Update state with new contacts data
      setContacts(contactsData);

      // Only update animations if contacts count changed
      if (contactsData.length !== fadeAnims.length) {
        setFadeAnims(contactsData.map(() => new Animated.Value(0)));
      }

      console.log("(NOBRIDGE) LOG Contact list updated from local storage");
    } catch (error) {
      console.error(
        "(NOBRIDGE) ERROR Error updating contacts from storage:",
        error.message
      );
    }
  };

  // Handle new messages - directly update UI without refreshing
  const handleNewMessage = useCallback(
    async (newMessage) => {
      try {
        if (
          !newMessage ||
          !newMessage.sentAt ||
          !newMessage.sender ||
          !newMessage.receiver
        ) {
          console.warn("(NOBRIDGE) WARN Invalid message format");
          return;
        }

        const isIncoming = newMessage.receiver.username === username;
        const contactName = isIncoming
          ? newMessage.sender.username
          : newMessage.receiver.username;

        if (!contactName) {
          console.warn("(NOBRIDGE) WARN No valid contact name in message");
          return;
        }

        // Verify the contact is in the contacts list before proceeding
        const storedContacts = await SecureStore.getItemAsync(
          `${username}_contacts`
        );
        let contactsList = storedContacts ? JSON.parse(storedContacts) : [];
        if (
          !Array.isArray(contactsList) ||
          !contactsList.includes(contactName)
        ) {
          console.log(
            `(NOBRIDGE) LOG Ignoring message from non-contact: ${contactName}`
          );
          return;
        }

        // Format message time
        const newTime = formatMessageTime(newMessage.sentAt);
        const newMessageDate = new Date(newMessage.sentAt).getTime();

        // Get the most up-to-date unread count from storage
        const messagesKey = `messages_${username}_${contactName}`;
        const storedMessagesStr = await SecureStore.getItemAsync(messagesKey);
        let storedMessages = storedMessagesStr
          ? JSON.parse(storedMessagesStr)
          : [];

        // Count unread messages
        const unreadCount = storedMessages.filter(
          (msg) =>
            (msg.receiver?.username === username ||
              (!msg.isMe && msg.sender?.username === contactName)) &&
            msg.status !== "seen"
        ).length;

        console.log(
          `(NOBRIDGE) LOG Contact ${contactName} has ${unreadCount} unread messages`
        );

        // Update the contacts state with accurate information
        setContacts((prevContacts) => {
          // Check if the contact is in the current UI list
          const contactIndex = prevContacts.findIndex(
            (c) => c.id === contactName
          );

          // Make a copy of current contacts
          const updatedContacts = [...prevContacts];

          // If contact already exists, update it
          if (contactIndex !== -1) {
            // Update contact details
            updatedContacts[contactIndex] = {
              ...updatedContacts[contactIndex],
              lastMessage: "Message",
              time: newTime,
              unread: unreadCount,
              latestMessageDate: newMessageDate,
            };
          } else {
            // If contact doesn't exist in UI, add it
            updatedContacts.push({
              id: contactName,
              name: contactName,
              lastMessage: "Message",
              time: newTime,
              unread: unreadCount,
              avatar: require("../../assets/profile.png"),
              latestMessageDate: newMessageDate,
            });
          }

          // Resort the list
          return updatedContacts.sort(
            (a, b) => b.latestMessageDate - a.latestMessageDate
          );
        });
      } catch (error) {
        console.error("(NOBRIDGE) ERROR Failed to handle new message:", error);
      }
    },
    [username, formatMessageTime]
  );

  // Initialize app
  useEffect(() => {
    if (!username || !userId) {
      console.log(
        "(NOBRIDGE) LOG Username or userId missing, redirecting to login"
      );
      navigation.reset({
        index: 0,
        routes: [{ name: "Login" }],
      });
      return;
    }

    // Flag to ensure loadResources only runs once
    let isMounted = true;
    let periodicCheckInterval = null;

    console.log(
      "(NOBRIDGE) LOG Setting up socket connection and message handlers"
    );

    const loadResources = async () => {
      if (!isMounted) return;

      try {
        await Font.loadAsync({
          "Roboto-Regular": {
            uri: "https://fonts.gstatic.com/s/roboto/v30/KFOmCnqEu92Fr1Mu4mxKKTU1Kg.woff2",
          },
          "Roboto-Medium": {
            uri: "https://fonts.gstatic.com/s/roboto/v30/KFOlCnqEu92Fr1MmEU9fBBc4AMP6lQ.woff2",
          },
          "Roboto-Bold": {
            uri: "https://fonts.gstatic.com/s/roboto/v30/KFOlCnqEu92Fr1MmWUlfBBc4AMP6lQ.woff2",
          },
        });
        setFontLoaded(true);
        console.log("(NOBRIDGE) LOG Fonts loaded successfully");

        // Only fetch messages once at start
        if (isMounted) {
          await fetchMessagesAndUpdateContacts();

          // Set up periodic check every 3 seconds (was 5 seconds)
          periodicCheckInterval = setInterval(periodicMessageCheck, 3000);
          console.log(
            "(NOBRIDGE) LOG Set up periodic message check interval (3s)"
          );
        }
      } catch (error) {
        console.error(
          "(NOBRIDGE) ERROR Error loading initial resources:",
          error.message
        );
      }
    };

    loadResources();

    const initializeSocket = async () => {
      const authToken = await SecureStore.getItemAsync("token");
      if (!authToken) {
        console.error("(NOBRIDGE) ERROR Socket: Authentication token missing");
        return;
      }

      socketRef.current = io(CONFIG.BACKEND_URL, {
        auth: { token: authToken },
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 10000,
        randomizationFactor: 0.5,
        timeout: 20000,
      });

      socketRef.current.on("connect", () => {
        console.log("(NOBRIDGE) LOG Socket.IO connected");
        socketRef.current.emit("register", userId.toString());
      });

      socketRef.current.on("new_message", async (newMessage) => {
        console.log(
          "(NOBRIDGE) LOG Socket received new_message event:",
          newMessage
        );

        // First try to process and store the message if it has content
        let processedMessage = null;
        if (newMessage.ciphertext && newMessage.nonce && newMessage.headers) {
          try {
            const authToken = await SecureStore.getItemAsync("token");
            if (authToken) {
              processedMessage = await processNewServerMessage(
                newMessage,
                authToken
              );
            }
          } catch (error) {
            console.error(
              "(NOBRIDGE) ERROR Failed to process socket message:",
              error.message
            );
          }
        }

        // Update UI with either the processed message or the original notification
        const messageToHandle = processedMessage || newMessage;
        await handleNewMessage(messageToHandle);

        // Always refresh contacts list to ensure counts are accurate
        setTimeout(() => {
          updateContactsFromLocalStorage();
        }, 500); // Short delay to ensure storage is updated first
      });

      socketRef.current.on("connect_error", (error) => {
        console.error(
          "(NOBRIDGE) ERROR Socket connection error:",
          error.message
        );
      });

      socketRef.current.on("disconnect", (reason) => {
        console.log(`(NOBRIDGE) LOG Socket disconnected: ${reason}`);
        // Don't attempt to reconnect if we're intentionally closing
        if (
          reason === "io client disconnect" ||
          reason === "io server disconnect"
        ) {
          socketRef.current.disconnect();
        }
      });

      // Add handler for message_deleted event
      socketRef.current.on("message_deleted", async ({ messageId }) => {
        console.log(`(NOBRIDGE) LOG Message deleted from server: ${messageId}`);

        // No need to refresh conversations - messages are only deleted from server
        console.log(
          `(NOBRIDGE) LOG Message ${messageId} deleted from server but UI not updated`
        );
      });
    };

    initializeSocket();

    const backHandler = BackHandler.addEventListener(
      "hardwareBackPress",
      () => {
        console.log("(NOBRIDGE) LOG Hardware back press blocked");
        return true; // Block hardware back press
      }
    );

    return () => {
      console.log("(NOBRIDGE) LOG Cleaning up MainScreen");
      isMounted = false;
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      if (periodicCheckInterval) {
        clearInterval(periodicCheckInterval);
      }
      backHandler.remove();
    };
  }, []); // Empty dependency array to run only once on mount

  // Ensure animations are properly managed when contacts change
  useEffect(() => {
    if (contacts.length > fadeAnims.length) {
      // Add new animation values for any new contacts
      const newAnims = [
        ...fadeAnims,
        ...Array(contacts.length - fadeAnims.length)
          .fill(0)
          .map(() => new Animated.Value(0)),
      ];
      setFadeAnims(newAnims);
    } else if (contacts.length < fadeAnims.length) {
      // Trim excess animation values
      setFadeAnims(fadeAnims.slice(0, contacts.length));
    }
  }, [contacts.length]);

  // Animate contacts when fadeAnims changes
  useEffect(() => {
    if (fadeAnims.length > 0 && contacts.length > 0) {
      fadeAnims.forEach((anim, index) => {
        // Only animate if needed
        if (anim._value < 1) {
          Animated.timing(anim, {
            toValue: 1,
            duration: 300,
            delay: index * 70,
            useNativeDriver: true,
          }).start();
        }
      });
    }
  }, [fadeAnims]);

  // Logout handler
  const handleLogout = async () => {
    console.log("(NOBRIDGE) LOG Logging out");
    if (socketRef.current) {
      socketRef.current.disconnect();
    }
    await SecureStore.deleteItemAsync("token");
    navigation.reset({
      index: 0,
      routes: [{ name: "Login" }],
    });
  };

  // Open chat handler
  const handleChatPress = (contact) => {
    console.log(`(NOBRIDGE) LOG Opening chat with ${contact.name}`);

    // Update local UI immediately
    setContacts((prevContacts) =>
      prevContacts.map((c) => (c.id === contact.id ? { ...c, unread: 0 } : c))
    );

    // Also update messages in secure storage to mark as read
    updateStoredMessagesAsRead(contact.name);

    navigation.navigate("Chat", {
      contact: {
        ...contact,
        status: "online",
      },
      userId,
      username,
    });
  };

  // Helper function to mark messages as read in storage
  const updateStoredMessagesAsRead = async (contactName) => {
    try {
      const messagesKey = `messages_${username}_${contactName}`;
      const storedMessagesStr = await SecureStore.getItemAsync(messagesKey);

      if (!storedMessagesStr) return;

      const storedMessages = JSON.parse(storedMessagesStr);
      if (!Array.isArray(storedMessages)) return;

      // Mark incoming messages as seen
      let hasChanges = false;
      const updatedMessages = storedMessages.map((msg) => {
        if (!msg.isMe && msg.status !== "seen") {
          hasChanges = true;
          return { ...msg, status: "seen" };
        }
        return msg;
      });

      // Only save if changes were made
      if (hasChanges) {
        await SecureStore.setItemAsync(
          messagesKey,
          JSON.stringify(updatedMessages)
        );
        console.log(
          `(NOBRIDGE) LOG Marked messages from ${contactName} as seen in storage`
        );
      }
    } catch (error) {
      console.error(
        `(NOBRIDGE) ERROR Failed to update message status: ${error.message}`
      );
    }
  };

  // Handle deleting chat from main screen
  const handleDeleteChat = useCallback(
    async (contact) => {
      try {
        console.log(
          `(NOBRIDGE) LOG Removing chat with ${contact.name} from main screen`
        );

        // Show confirmation alert before deleting
        Alert.alert(
          "Delete Chat",
          `Are you sure you want to delete all messages with ${contact.name}?`,
          [
            {
              text: "Cancel",
              style: "cancel",
            },
            {
              text: "Delete",
              style: "destructive",
              onPress: async () => {
                try {
                  // Remove messages from local storage
                  const messagesKey = `messages_${username}_${contact.name}`;
                  await SecureStore.deleteItemAsync(messagesKey);

                  // Update the contacts list to remove this chat from the display only
                  setContacts((prevContacts) => {
                    const newContacts = prevContacts.filter(
                      (c) => c.id !== contact.id
                    );

                    // Update fade animations array to match new contacts length
                    // This needs to be inside the setContacts to have access to prevContacts
                    setFadeAnims(newContacts.map(() => new Animated.Value(1)));

                    return newContacts;
                  });

                  console.log(
                    `(NOBRIDGE) LOG Successfully cleared local data for ${contact.name}`
                  );
                } catch (error) {
                  console.error(
                    `(NOBRIDGE) ERROR Failed to delete chat with ${contact.name}:`,
                    error
                  );
                  Alert.alert(
                    "Error",
                    "Failed to delete chat. Please try again."
                  );
                }
              },
            },
          ]
        );
      } catch (error) {
        console.error(
          `(NOBRIDGE) ERROR Failed to delete chat with ${contact.name}:`,
          error
        );
        Alert.alert("Error", "Failed to delete chat. Please try again.");
      }
    },
    [username]
  );

  // Render swipe right actions (delete button)
  const renderRightActions = useCallback(
    (contact) => {
      return (
        <TouchableOpacity
          style={styles.deleteAction}
          onPress={() => handleDeleteChat(contact)}
        >
          <Ionicons name="close-circle" size={28} color="white" />
        </TouchableOpacity>
      );
    },
    [handleDeleteChat]
  );

  // Render chat item
  const renderChatItem = useCallback(
    ({ item, index }) => {
      // Default to a fully visible animation if no animation value exists
      const fadeAnim =
        index < fadeAnims.length ? fadeAnims[index] : new Animated.Value(1);

      return (
        <Animated.View style={{ opacity: fadeAnim }}>
          <Swipeable
            renderRightActions={() => renderRightActions(item)}
            friction={2}
            rightThreshold={40}
          >
            <TouchableOpacity
              style={styles.chatItem}
              onPress={() => handleChatPress(item)}
            >
              <Image source={item.avatar} style={styles.chatAvatar} />
              <View style={styles.chatContent}>
                <View style={styles.chatHeader}>
                  <Text
                    style={[
                      styles.chatName,
                      fontLoaded && { fontFamily: "Roboto-Medium" },
                    ]}
                  >
                    {item.name || "Unknown"}
                  </Text>
                  <View style={styles.timeAndUnreadContainer}>
                    <Text
                      style={[
                        styles.chatTime,
                        fontLoaded && { fontFamily: "Roboto-Regular" },
                      ]}
                    >
                      {item.time}
                    </Text>
                    {item.unread > 0 && (
                      <View style={styles.unreadBadge}>
                        <Text
                          style={[
                            styles.unreadCount,
                            fontLoaded && { fontFamily: "Roboto-Bold" },
                          ]}
                        >
                          {item.unread}
                        </Text>
                      </View>
                    )}
                  </View>
                </View>
                <View style={styles.chatFooter}>
                  <Text
                    style={[
                      styles.chatMessage,
                      item.unread > 0 && styles.unreadMessage,
                      fontLoaded && { fontFamily: "Roboto-Regular" },
                    ]}
                    numberOfLines={1}
                  >
                    {item.lastMessage}
                  </Text>
                </View>
              </View>
            </TouchableOpacity>
          </Swipeable>
        </Animated.View>
      );
    },
    [fontLoaded, fadeAnims, handleChatPress, renderRightActions]
  );

  // Empty state component
  const renderEmptyList = () => (
    <View style={styles.emptyContainer}>
      <Ionicons name="chatbubbles-outline" size={60} color="#888" />
      <Text
        style={[
          styles.emptyText,
          fontLoaded && { fontFamily: "Roboto-Regular" },
        ]}
      >
        No chats yet. Start a new conversation!
      </Text>
    </View>
  );

  // Add a focus listener to ensure we're always registered as online when returning to this screen
  useEffect(() => {
    const unsubscribe = navigation.addListener("focus", () => {
      console.log("(NOBRIDGE) LOG MainScreen focused - ensuring online status");

      // Re-emit register event to ensure we're marked as online
      if (socketRef.current && socketRef.current.connected && userId) {
        socketRef.current.emit("register", userId.toString());
        console.log(
          `(NOBRIDGE) LOG Re-registered user ${userId} as online after navigation`
        );
      } else if (socketRef.current && !socketRef.current.connected && userId) {
        console.log("(NOBRIDGE) LOG Socket disconnected - reconnecting...");
        // Try to reconnect if somehow disconnected
        socketRef.current.connect();

        // Re-register after a short delay to ensure connection is established
        setTimeout(() => {
          if (socketRef.current && socketRef.current.connected) {
            socketRef.current.emit("register", userId.toString());
            console.log(
              `(NOBRIDGE) LOG Re-registered user ${userId} after reconnection`
            );
          }
        }, 1000);
      }

      // Update contacts list to refresh unread counts
      updateContactsFromLocalStorage();
    });

    return () => {
      // In newer versions of React Navigation, the listener returns an unsubscribe function directly
      unsubscribe();
    };
  }, [navigation, userId, updateContactsFromLocalStorage]);

  if (!fontLoaded) {
    console.log("(NOBRIDGE) LOG Fonts not loaded, rendering null");
    return null;
  }

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      style={{ flex: 1 }}
    >
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#252762" />
        <View style={styles.header}>
          <Image
            source={require("../../assets/profile.png")}
            style={styles.profileImage}
          />
          <Text
            style={[
              styles.username,
              fontLoaded && { fontFamily: "Roboto-Bold" },
            ]}
            numberOfLines={1}
          >
            {username || "User"}
          </Text>
          <TouchableOpacity onPress={handleLogout} style={styles.logoutButton}>
            <Image
              source={require("../../assets/shutdown.png")}
              style={styles.logoutIcon}
            />
          </TouchableOpacity>
        </View>
        {isRefreshing && contacts.length === 0 ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color="#4A80F0" />
            <Text style={styles.loadingText}>Loading chats...</Text>
          </View>
        ) : (
          <FlatList
            data={contacts}
            keyExtractor={(item) => item.id || `contact-${item.name}`}
            renderItem={renderChatItem}
            contentContainerStyle={[
              styles.listContent,
              contacts.length === 0 && styles.emptyListContent,
            ]}
            showsVerticalScrollIndicator={false}
            ListEmptyComponent={renderEmptyList}
            extraData={[contacts, fadeAnims]}
            onRefresh={fetchMessagesAndUpdateContacts}
            refreshing={isRefreshing}
          />
        )}
        <TouchableOpacity
          style={styles.fab}
          onPress={() =>
            navigation.navigate("Contacts", { token, userId, username })
          }
        >
          <Ionicons name="create-outline" size={30} color="white" />
        </TouchableOpacity>
        <View style={styles.bottomNav}>
          <TouchableOpacity style={styles.navItemActive}>
            <Image
              source={require("../../assets/chats.png")}
              style={[styles.icon, { tintColor: "#4A80F0" }]}
            />
            <Text
              style={[
                styles.navTextActive,
                fontLoaded && { fontFamily: "Roboto-Medium" },
              ]}
            >
              Chats
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.navItem}
            onPress={() =>
              navigation.navigate("Contacts", { token, userId, username })
            }
          >
            <Ionicons name="people-outline" size={24} color="#888" />
            <Text
              style={[
                styles.navText,
                fontLoaded && { fontFamily: "Roboto-Medium" },
              ]}
            >
              Contacts
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.navItem}
            onPress={() => navigation.navigate("Settings", { userId })}
          >
            <Image
              source={require("../../assets/settings.png")}
              style={[styles.icon, { tintColor: "#888" }]}
            />
            <Text
              style={[
                styles.navText,
                fontLoaded && { fontFamily: "Roboto-Medium" },
              ]}
            >
              Settings
            </Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#252762" },
  header: {
    flexDirection: "row",
    alignItems: "center",
    padding: 12,
    paddingTop: 8,
    backgroundColor: "#252762",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.2,
    shadowRadius: 4,
    elevation: 3,
    borderBottomWidth: 1,
    borderBottomColor: "#fff",
  },
  profileImage: {
    width: 44,
    height: 44,
    borderRadius: 22,
    marginRight: 12,
    borderWidth: 2,
    borderColor: "#ffffff33",
  },
  username: {
    color: "white",
    fontSize: 22,
    flex: 1,
    textShadowColor: "rgba(255, 255, 255, 0.3)",
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 10,
  },
  logoutButton: {
    padding: 8,
  },
  logoutIcon: {
    width: 28,
    height: 28,
    tintColor: "white",
  },
  listContent: {
    paddingBottom: 80,
    paddingTop: 12,
  },
  chatItem: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 15,
    paddingVertical: 12,
    borderBottomWidth: 0.5,
    borderBottomColor: "#ffffff11",
    backgroundColor: "rgba(255, 255, 255, 0.05)",
    marginHorizontal: 10,
    marginVertical: 5,
    borderRadius: 12,
  },
  chatAvatar: {
    width: 50,
    height: 50,
    borderRadius: 25,
    marginRight: 12,
    borderWidth: 2,
    borderColor: "#ffffff33",
  },
  chatContent: { flex: 1 },
  chatHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 4,
  },
  chatName: {
    color: "white",
    fontSize: 17,
    fontWeight: "600",
  },
  chatTime: {
    color: "#888",
    fontSize: 12,
  },
  timeAndUnreadContainer: {
    alignItems: "flex-end",
  },
  unreadBadge: {
    backgroundColor: "#4A80F0",
    borderRadius: 10,
    minWidth: 20,
    height: 20,
    justifyContent: "center",
    alignItems: "center",
    marginTop: 4,
    paddingHorizontal: 6,
    shadowColor: "#4A80F0",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 4,
  },
  unreadCount: {
    color: "white",
    fontSize: 12,
    fontWeight: "600",
  },
  chatFooter: {
    flexDirection: "row",
    justifyContent: "space-between",
  },
  chatMessage: {
    color: "#888",
    fontSize: 14,
    flex: 1,
    marginRight: 10,
  },
  unreadMessage: {
    color: "white",
    fontWeight: "500",
  },
  fab: {
    position: "absolute",
    right: 20,
    bottom: 80,
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: "#4A80F0",
    justifyContent: "center",
    alignItems: "center",
    elevation: 6,
    shadowColor: "#4A80F0",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 6,
  },
  bottomNav: {
    flexDirection: "row",
    justifyContent: "space-around",
    paddingVertical: 8,
    backgroundColor: "#252762",
    borderTopWidth: 1,
    borderTopColor: "#fff",
  },
  navItem: {
    alignItems: "center",
    padding: 8,
    flex: 1,
  },
  navItemActive: {
    alignItems: "center",
    padding: 8,
    flex: 1,
  },
  navText: {
    color: "#888",
    fontSize: 12,
    marginTop: 4,
  },
  navTextActive: {
    color: "#4A80F0",
    fontSize: 12,
    marginTop: 4,
    fontWeight: "600",
  },
  icon: {
    width: 24,
    height: 24,
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
  deleteAction: {
    backgroundColor: "#FF3B30",
    width: 80,
    justifyContent: "center",
    alignItems: "center",
    borderRadius: 10,
    marginVertical: 5,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    paddingBottom: 50,
  },
  loadingText: {
    color: "#888",
    fontSize: 16,
    marginTop: 10,
  },
  emptyListContent: {
    flexGrow: 1,
    justifyContent: "center",
  },
});

export default MainScreen;
