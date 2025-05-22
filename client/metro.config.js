const { getDefaultConfig } = require("expo/metro-config");

module.exports = (async () => {
  const config = await getDefaultConfig(__dirname);
  return {
    ...config,
    resolver: {
      ...config.resolver,
      sourceExts: [...config.resolver.sourceExts, "cjs", "mjs", "wasm"],
      assetExts: [...config.resolver.assetExts, "wasm"],
      extraNodeModules: {
        crypto: require.resolve("react-native-get-random-values"),
        buffer: require.resolve("buffer"),
        sodium: require.resolve("libsodium-wrappers"),
      },
    },
  };
})();
