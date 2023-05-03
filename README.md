## Encryptor
Encryption/decryption of text with a password.

### Example
#### Encrypt
```
encryption = Encryptor()
encryption.encrypt('Hello! I\'m Pavel.', '12345')

0Rct1if6fzFAwuKScQyaSwABhqCAAAAAAGRStwHkRsSebdsBu2xfnWcCwTB9PRLv1CoTiZwsLPzSHx_ZVD7HoxV9FomY3rqNdwbmU5emJ1YUTjqPgBqHr43GKzcSPuNUqOnIDS4Z5PxNYeO1Yg==
```

#### Decrypt
```
decryption = Encryptor()
decryption.decrypt('0Rct1if6fzFAwuKScQyaSwABhqCAAAAAAGRStwHkRsSebdsBu2xfnWcCwTB9PRLv1CoTiZwsLPzSHx_ZVD7HoxV9FomY3rqNdwbmU5emJ1YUTjqPgBqHr43GKzcSPuNUqOnIDS4Z5PxNYeO1Yg==', '12345')

Hello! I'm Pavel.
```

Invalid password:
```
decryption = Encryptor()
decryption.decrypt('0Rct1if6fzFAwuKScQyaSwABhqCAAAAAAGRStwHkRsSebdsBu2xfnWcCwTB9PRLv1CoTiZwsLPzSHx_ZVD7HoxV9FomY3rqNdwbmU5emJ1YUTjqPgBqHr43GKzcSPuNUqOnIDS4Z5PxNYeO1Yg==', '123456789')

Got invalid token or password.
```