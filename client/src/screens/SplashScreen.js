import React, { useEffect, useRef } from "react";
import {
  View,
  Text,
  Image,
  Animated,
  StyleSheet,
  Dimensions,
  StatusBar,
} from "react-native";
import * as SecureStore from "expo-secure-store";

const { width, height } = Dimensions.get("window");

const SplashScreen = ({ navigation }) => {
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const scaleAnim = useRef(new Animated.Value(0.8)).current;
  const slideUpAnim = useRef(new Animated.Value(50)).current;

  useEffect(() => {
    // Combined animation sequence
    Animated.parallel([
      Animated.timing(fadeAnim, {
        toValue: 1,
        duration: 1200,
        useNativeDriver: true,
      }),
      Animated.timing(scaleAnim, {
        toValue: 1,
        duration: 1200,
        useNativeDriver: true,
      }),
      Animated.timing(slideUpAnim, {
        toValue: 0,
        duration: 1200,
        useNativeDriver: true,
      }),
    ]).start();

    // Check if user is registered
    const checkRegistration = async () => {
      try {
        const storedUsername = await SecureStore.getItemAsync("username");
        const nextScreen = storedUsername ? "Login" : "Register";

        // Wait 2 seconds before transitioning
        setTimeout(() => {
          Animated.parallel([
            Animated.timing(fadeAnim, {
              toValue: 0,
              duration: 800,
              useNativeDriver: true,
            }),
            Animated.timing(scaleAnim, {
              toValue: 0.8,
              duration: 800,
              useNativeDriver: true,
            }),
            Animated.timing(slideUpAnim, {
              toValue: -50,
              duration: 800,
              useNativeDriver: true,
            }),
          ]).start(() => {
            navigation.replace(nextScreen);
          });
        }, 2000);
      } catch (error) {
        console.error("Failed to check registration:", error);
        navigation.replace("Register");
      }
    };

    checkRegistration();
  }, [navigation, fadeAnim, scaleAnim, slideUpAnim]);

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#252762" />
      <Animated.View
        style={[
          styles.logoContainer,
          {
            opacity: fadeAnim,
            transform: [{ scale: scaleAnim }, { translateY: slideUpAnim }],
          },
        ]}
      >
        <Image source={require("../../assets/logo.png")} style={styles.logo} />
        <Animated.Text
          style={[
            styles.title,
            {
              opacity: fadeAnim,
              transform: [
                {
                  translateY: fadeAnim.interpolate({
                    inputRange: [0, 1],
                    outputRange: [20, 0],
                  }),
                },
              ],
            },
          ]}
        >
          Silent
        </Animated.Text>
        <Animated.Text
          style={[
            styles.subtitle,
            {
              opacity: fadeAnim,
              transform: [
                {
                  translateY: fadeAnim.interpolate({
                    inputRange: [0, 1],
                    outputRange: [20, 0],
                  }),
                },
              ],
            },
          ]}
        >
          Secure Messenger
        </Animated.Text>
      </Animated.View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#252762",
    alignItems: "center",
    justifyContent: "center",
  },
  logoContainer: {
    alignItems: "center",
    justifyContent: "center",
  },
  logo: {
    width: 180,
    height: 180,
    borderRadius: 90,
    marginBottom: 20,
    shadowColor: "#fff",
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.3,
    shadowRadius: 20,
    elevation: 10,
  },
  title: {
    fontSize: 48,
    color: "white",
    fontWeight: "bold",
    marginTop: 20,
    textShadowColor: "rgba(255,255,255,0.5)",
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 15,
  },
  subtitle: {
    fontSize: 22,
    color: "white",
    marginTop: 10,
    textShadowColor: "rgba(255,255,255,0.3)",
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 10,
  },
});

export default SplashScreen;
