# Silent - Secure End-to-End Encrypted Messaging

Silent is a modern, high-security messaging application that implements state-of-the-art cryptographic protocols to ensure your conversations remain private, secure, and only accessible to you and your intended recipients.

![Silent App Logo](assets/logo.png)

## Features

- **True End-to-End Encryption**: Messages are encrypted on your device and can only be decrypted by the recipient
- **Perfect Forward Secrecy**: Using the Double Ratchet Algorithm, each message uses a new encryption key
- **Self-Destructing Messages**: Messages are automatically deleted from the server after being read
- **Offline Messaging**: Messages are stored securely until the recipient comes online
- **Media Sharing**: Share images securely with end-to-end encryption
- **Contact Verification**: Verify your contacts through secure invitation system
- **No Phone Number Required**: Use a username instead of phone number for enhanced privacy
- **Local Message Storage**: Messages are stored securely on your device using SecureStore

## Security Architecture

Silent implements multiple layers of security:

- **X3DH (Extended Triple Diffie-Hellman)** for secure key exchange and initial authentication
- **Double Ratchet Algorithm** (same protocol used by Signal) for perfect forward secrecy
- **XSalsa20** encryption for message content with 256-bit keys
- **Enhanced Entropy** using Python-seeded random number generation
- **NaCl/TweetNaCl** cryptographic library for proven security primitives
- **Message Self-Destruction** once read and acknowledged
- **Secure Local Storage** using Expo SecureStore for encrypted message persistence

## Technical Stack

### Frontend (Mobile App)

- React Native with Expo
- TweetNaCl.js for cryptography
- SecureStore for secure local storage
- Socket.io client for real-time communication

### Backend

- Node.js with Express
- MongoDB for temporary message storage
- Socket.io for real-time messaging
- JWT for authentication

## Supported Media Formats

Silent supports the following media formats for secure sharing:

- Images: JPEG, PNG
- Videos: MP4, MOV (up to 5MB)

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- MongoDB (v4.4 or higher)
- Expo CLI (`npm install -g expo-cli`)
- Android Studio (for Android development) or Xcode (for iOS development)

### Installation

#### Server Setup

1. Clone the repository

   ```
   git clone https://github.com/your-username/Silent.git
   cd Silent/server
   ```

2. Install dependencies

   ```
   npm install
   ```

3. Create SSL certificates (for local development)

   ```
   ./generate-ssl.sh
   ```

4. Set up environment variables
   Create a `.env` file in the server directory with the following variables:

   ```
   PORT=3000
   MONGO_URI=mongodb://localhost:27017/silent
   JWT_SECRET=your_jwt_secret_key
   NODE_ENV=development
   ```

5. Start the server
   ```
   npm start
   ```

#### Client Setup

1. Navigate to the client directory

   ```
   cd ../client
   ```

2. Install dependencies

   ```
   npm install
   ```

3. Configure the application
   Edit `src/config/config.js` to point to your server address

4. Start the Expo development server

   ```
   expo start
   ```

5. Run on device or emulator
   - Press 'a' to run on Android emulator
   - Press 'i' to run on iOS simulator
   - Or scan the QR code with the Expo Go app on your device

## Usage

1. **Registration**: Create a new account using a username and password
2. **Adding Contacts**: Search for users and send contact requests
3. **Messaging**: Start encrypted conversations with accepted contacts
4. **Media Sharing**: Share images and videos securely
5. **Message Status**: Track when messages are sent, delivered, and seen

## Security Considerations

- Silent is designed for maximum security and privacy
- All message content is encrypted on the sender's device and can only be decrypted on the recipient's device
- The server never has access to decryption keys or message content
- Messages are removed from the server after delivery and confirmation
- All cryptographic operations use proven libraries and algorithms

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Signal Protocol for inspiration on the Double Ratchet Algorithm
- The TweetNaCl.js team for their lightweight cryptographic library
- The Expo team for their secure storage solutions

---
