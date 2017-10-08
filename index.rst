..  Building this document:
    make latexpdf

NuCypher KMS: decentralized key management system. Implementation whitepaper
===============================================================================

Overview
==============
This implementation white paper describes the first working version of the NuCypher KMS, a decentralized Key Management System [KMS-whitepaper]_.
This first version is focused on enforcing correctness of operation.
Providing incentives for not leaking re-encryption keys will not be the goal of this first release.

The white paper introduces all the network participants, giving them human names an defining function of each.
Then it describes encryption/decryption and re-encryption algorithms used.
Next, we describe how the decentralized network is built.
After that, we describe how the correctness of re-encryption is enforced on Ethereum blockchain.
Before the on-chain functionality is fully ready, we deploy a semi-trusted centralized service which will serve as a working mock for the consensus piece of
the protocol.

The code for NuCypher KMS can be found on github [KMS-github]_.

.. [KMS-whitepaper] https://arxiv.org/abs/1707.06140
.. [KMS-github] https://github.com/nucypher/nucypher-kms

Main characters
==================
There are three main types of participants in NuCypher KMS network: Alice, Bob and Ursula.

**Alice** is the character who is the original data owner.
Alice has an encrypting keypair ``privkey_enc_a / pubkey_enc_a`` and a signing key pair ``privkey_sig_a / pubkey_sig_a``.
Alice originally encrypts data for herself using ``pubkey_enc_a``.
She uses ``privkey_sig_a`` whenever she wants to prove her identity.

**Bob** is the character who Alice grants access to.
Once Alice shares some ``subpath`` with Bob, he can read all the data within this ``subpath``.
Bob has an encrypting keypair ``privkey_enc_b / pubkey_enc_b`` and a signing key pair ``privkey_sig_b / pubkey_sig_b``.
After Alice shared something with Bob, he can use his ``privkey_enc_b`` to decrypt that data.

**Ursula** is the name for network participants who enable data sharing.
She is the one who is performing proxy re-encryption [PRE]_ on the ciphertexts originally produced by Alice.
She is the *proxy* in proxy re-encryption schemes.
Output of Ursula's operation will be used by Bob to decrypt Alice's data.
Ursula is is the character who provides the core functionality of NuCypher KMS.
Most often all the "mining" NuCypher KMS nodes will be called by the name Ursula.

.. [PRE] https://en.wikipedia.org/wiki/Proxy_re-encryption

Cryptographic algorithms used
===========================

Public key encryption
------------------------
Conceptually, public key encryption algorithms encrypt data using public key (which is publicly known) and decrypt using private (or secret) key::

    encrypted_data = encrypt_pub(pubkey_enc, data)
    decrypted_data = decrypt_pub(privkey_enc, encrypted_data)
    assert data == decrypted_data

For public key encryption we use Integrated Encryption Scheme [ECIES]_.
This scheme is both CPA-secure [CPA-security]_ and CCA-secure [CCA-security]_.
We use elliptic curve cryptography on the curve *secp256k1* (the same as Bitcoin and Ethereum uses).

In order to encrypt the bulk of the data, usually *symmetric encryption* is used.
ECIES normally works in such a way that it generates a symmetric key to be used (it's a Diffie-Hellman secret which the recipient of the data can reconstruct).
In our case, we want to have the same symmetric key encrypted for multiple paths.
Hence, we encrypt a random per-file symmetric key with the generated key, and the file content is encrypted by the per-file symmetric key itself.

The concept of generating a shares secret by ECIES can be expressed with the following pseudocode::

    shared_secret, ciphertext = ecies.encapsulate(pubkey_enc)
    decrypted_shared_secret = ecies.decapsulate(privkey_enc)
    assert shared_secret == decrypted_shared_secret

The ``shared_secret`` will be available to both encrypting and decrypting person.

.. [ECIES] https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
.. [CPA-security] https://en.wikipedia.org/wiki/Chosen-plaintext_attack
.. [CCA-security] https://en.wikipedia.org/wiki/Chosen-ciphertext_attack

Symmetric encryption. Hybrid encryption
-----------------------------------------
Using public key encryption straight away for encrypting bulk of the data would be very slow (each operation on a 256-bit elliptic curve takes about quarter of
a millisecond).
So, for encrypting the bulk of the data we use symmetric block ciphers::

    encrypted_data = encrypt_sym(sym_key, data)
    decrypted_data = decrypt_sym(sym_key, encrypted_data)
    assert data == decrypted_data

For the symmetric block cipher, we use NaCl's SecretBox which uses Salsa20 for encryption and Poly1305 for authentication [NaCl]_.
In particular, we use a Python wrapper [PyNaCl]_.

We use symmetric encryption in conjunction with public key encryption by ECIES.
The pseudocode for this::

    sym_key, enc_sym_key = ecies.encapsulate(pubkey_enc)
    encrypted_data = encrypt_sym(sym_key, data)
    # enc_sym_key stored with encrypted_data
    ...

    sym_key = ecies.decapsulate(privkey_enc, enc_sym_key)
    decrypted_data = decrypt_sym(sym_key, encrypted_data)
    assert decrypted_data == data

.. [NaCl] https://nacl.cr.yp.to
.. [PyNaCl] http://pynacl.readthedocs.io/en/latest/secret/

Key per subpath
------------------

Proxy re-encryption
---------------------

Split-key re-encryption
--------------------------

Digital signatures
--------------------

Network discovery
====================

Correctness of re-encryption
==============================

Enforcing correctness on Ethereum blockchain
===============================================

Centralized stub to mock trustless functionality
=================================================

Conclusion
============
