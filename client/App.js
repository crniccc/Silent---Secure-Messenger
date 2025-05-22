import "./crypto-polyfill";
import React, { useEffect, useState } from "react";
import { SafeAreaView, StatusBar, LogBox } from "react-native";
import AppNavigator from "./src/navigation/AppNavigator";
import enhancedRandom from "./src/utils/EnhancedRandom";
import serverEnhancedRandom from "./src/utils/ServerEnhancedRandom";

// Suppress the bcrypt warning about Math.random
LogBox.ignoreLogs(["Using Math.random is not cryptographically secure!"]);

const App = () => {
  const [initialized, setInitialized] = useState(false);

  // Initialize enhanced randomness system at app startup
  useEffect(() => {
    const initializeSecuritySystems = async () => {
      try {
        console.log("Initializing enhanced randomness system...");
        // First initialize the local randomness system
        await enhancedRandom.initialize();
        console.log("Local enhanced randomness initialized");

        // Then initialize the server-enhanced randomness system
        // This already has fallback mechanisms built in
        await serverEnhancedRandom.initialize().catch((err) => {
          console.log(
            "Server-enhanced randomness init had issues, but app will continue:",
            err.message
          );
        });
        console.log(
          "Entropy server available:",
          serverEnhancedRandom.serverAvailable
        );

        console.log("Enhanced randomness system initialized successfully");
        setInitialized(true);
      } catch (error) {
        console.error("Failed to initialize enhanced randomness:", error);
        // Even if there's an error, we should still allow the app to run
        // The cryptographic operations will fall back to local randomness
        setInitialized(true);
      }
    };

    initializeSecuritySystems();
  }, []);

  // We still render the app even if initialization fails
  // The crypto operations have fallbacks built in
  return (
    <SafeAreaView style={{ flex: 1 }}>
      <StatusBar barStyle="light-content" backgroundColor="#1a1a1d" />
      <AppNavigator initialRoute="Splash" />
    </SafeAreaView>
  );
};

export default App;
