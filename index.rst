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
We use elliptic curve cryptography on the curve *secp256k1* (the same as Bitcoin and Ethereum uses).

In order to encrypt the bulk of the data, usually *symmetric encryption* is used.
ECIES normally works in such a way that it generates a symmetric key to be used (it's a Diffie-Hellman secret which the recipient of the data can reconstruct).
In our case, we want to have the same symmetric key encrypted for multiple paths.
Hence, we encrypt a random per-file symmetric key with the generated key, and the file content is encrypted by the per-file symmetric key itself.

.. [ECIES] https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme

Symmetric encryption
-----------------------

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
