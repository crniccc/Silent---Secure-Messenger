import React from "react";
import { createStackNavigator } from "@react-navigation/stack";
import { NavigationContainer } from "@react-navigation/native";
import SplashScreen from "../screens/SplashScreen";
import LoginScreen from "../screens/LoginScreen";
import RegisterScreen from "../screens/RegisterScreen";
import MainScreen from "../screens/MainScreen";
import SettingsScreen from "../screens/SettingsScreen";
import ChatScreen from "../screens/ChatScreen";
import ContactsScreen from "../screens/ContactsScreen";
import SafePasswordSetup from "../screens/SafePasswordSetup";
import ChangePassword from "../screens/ChangePassword";
import DeleteConfirmation from "../screens/DeleteConfirmation";

const Stack = createStackNavigator();

const AppNavigator = ({ initialRoute }) => {
  return (
    <NavigationContainer>
      <Stack.Navigator
        initialRouteName={initialRoute || "Splash"}
        screenOptions={{
          headerShown: false,
          gestureEnabled: true, // Enable gestures by default
        }}
      >
        <Stack.Screen name="Splash" component={SplashScreen} />
        <Stack.Screen
          name="Login"
          component={LoginScreen}
          options={{
            gestureEnabled: false, // Disable swipe navigation
          }}
        />
        <Stack.Screen
          name="Register"
          component={RegisterScreen}
          options={{
            gestureEnabled: false, // Disable swipe navigation
          }}
        />
        <Stack.Screen
          name="Main"
          component={MainScreen}
          options={{
            gestureEnabled: false, // Disable only for MainScreen
          }}
        />
        <Stack.Screen name="Settings" component={SettingsScreen} />
        <Stack.Screen name="Chat" component={ChatScreen} />
        <Stack.Screen
          name="Contacts"
          component={ContactsScreen}
          initialParams={{ token: null, userId: null, username: null }}
        />
        <Stack.Screen
          name="NewChat"
          component={ContactsScreen}
          initialParams={{ token: null, userId: null, username: null }}
        />
        <Stack.Screen name="SafePasswordSetup" component={SafePasswordSetup} />
        <Stack.Screen name="ChangePassword" component={ChangePassword} />
        <Stack.Screen
          name="DeleteConfirmation"
          component={DeleteConfirmation}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
};

export default AppNavigator;
