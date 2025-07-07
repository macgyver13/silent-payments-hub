# [Setup](https://github.com/BlueWallet/SilentPayments/pull/21)
#### install prerequisites 
```
#nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash

# install nodejs
nvm install 22
```

#### configure SilentPayments
```
git clone https://github.com/BlueWallet/SilentPayments.git
cd SilentPayments
git checkout add-tweak-calculation
npm install
```

# Testing

Date: 2025-06-23 [6613838](https://github.com/BlueWallet/SilentPayments/commit/6613838a86fd03e2091781f4814167ccecc7c9b4)
#### Evaluate BIP 352 test vectors
```
npm run test
```

## Test BlueWallet iOS App 
*(does not support Silent Payments **June 25 2025**)*
#### configure BlueWallet
```
git clone https://github.com/BlueWallet/BlueWallet.git
cd BlueWallet
npx pod-install
```

### configure BlueWallet iOS App for Simulator
- Open Xcode *Workspace* ios/BlueWallet.xcworkspace
- disabled codesigning **Target::BlueWallet->Signing & Capabilities->Signing (Debug)**
	- toggle Automatically manage signing on then off
- removed **Target::BlueWallet->Signing & Capabilities->Push Notifications**
- removed other Targets Watch, 
- modified node path for **Target::BlueWallet->Build Phases->Bundle React Native code and images**
```
export EXTRA_PACKAGER_ARGS="--sourcemap-output $TMPDIR/$(md5 -qs "$CONFIGURATION_BUILD_DIR")-main.jsbundle.map"
export NODE_BINARY=/Users/<user>/.nvm/versions/node/v22.16.0/bin/node
../node_modules/react-native/scripts/react-native-xcode.sh
```

*building the BlueWallet target and **Run** should work now* (tested MacOS and iOS Simulator)

#### Start React Native Dev Tools
```
npm start
```

