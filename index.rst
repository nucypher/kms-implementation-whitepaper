..  Building this document:
    make latexpdf

NuCypher KMS: decentralized key management system. Implementation whitepaper
===============================================================================

Overview
==============
This implementation white paper describes the first working version of the NuCypher KMS, a decentralized Key Management System [KMS-whitepaper]_.
This first version is focused on enforcing correctness of operation.
Providing incentives for not leaking re-encryption keys will not be the goal of this first release.

The white paper introduces all the network participants, giving them human names and defining function of each.
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

The concept of generating a shared secret by ECIES can be expressed with the following pseudocode::

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
We are able to share not only individual files, or not only Alice's data, but also each subpath Alice has in her file structure (it can be generalized to
non-file hierarchical data also).
For example, for each path ``'/path/to/file.txt'`` there will be derived keys for *subpaths* ``'/'``, ``'/path'``, ``'/path/to'`` and ``'/path/to/file.txt'``.
The key is derived using *keccak256* hash function which is not susceptible to length extension attack.
We use the derived key as a private key to encrypt for in ECIES.
The full pseudocode of encrypting a file with all the subpath keys::


    content_key = secure_random(key_length)
    encrypted_data = encrypt_sym(content_key, data)

    for subpath in subpaths:
        privkey_sub[subpath] = keccak_hash(privkey_enc + subpath)
        pubkey_sub[subpath] = priv2pub(privkey_sub[subpath])

        derived_key_sub, enc_derived_key_sub = ecies.encapsulate(pubkey_sub[subpath])
        encrypted_content_key = encrypt_sym(derived_key_sub, content_key)
        enc_sub_keys[subpath] = (enc_derived_key_sub, encrypted_content_key)
    ...

    # Now if we've got access to subpath
    # The recepient needs (enc_derived_key_sub, encrypted_content_key), encrypted_data and the the private key privkey_sub[subpath]
    enc_derived_key_sub, encrypted_content_key = enc_sub_keys[subpath]

    derived_key_sub = ecies.decapsulate(privkey_sub[subpath], enc_derived_key_sub)
    content_key = decrypt_sym(derived_key_sub, encrypted_content_key)
    decrypted_data = decrypt_sym(content_key, encrypted_data)
    assert decrypted_data == data

Proxy re-encryption
---------------------
Conceptually, proxy re-encryption is a way to delegate an untrusted third party to transform data encrypted under one key to be decryptable by another.
In our case, Alice initially encrypts data under ``pubkey_enc_a`` (or a derived key) originally.
When Bob comes along with his public key, Alice creates a re-encryption key ``re_ab`` out of ``privkey_enc_a`` and ``pubkey_enc_b``::
Using ``re_ab``, Ursula can execute re-encryption to make data decryptable by Bob.
The whole flow conceptually::

    # Alice's side
    ciphertext_alice = encrypt(pubkey_enc_a, data)
    re_ab = rekey(privkey_enc_a, pubkey_enc_b)

    # Ursula's side
    ciphertext_bob = reencrypt(re_ab, ciphertext_alice)

    # Bob's side
    data = decrypt(privkey_enc_b, ciphertext_bob)

The ciphertext ``ciphertext_alice`` is, in fact, ``(enc_derived_key_sub, encrypted_content_key)`` when ECIES is used.
Decryption of this ciphertext gives Bob a symmetric key to decrypt ``encrypted_data`` when a hybrid (public key + symmetric) encryption is used.

There are two types of re-encryption algorithms: *interactive* (where Alice needs Bob's *private* key to create a re-encryption key) and *non-interactive*
(where Alice uses Bob's public key, as described above).
We've created a proxy re-encryption algorithm for ECIES, but intrinsically it's interactive, whereas we need a non-interactive one.
Fortunately, there is a way to convert one to another::

    def noninteractive_rekey(privkey_a, pubkey_b):
        privkey_eph = secure_random()
        return (interactive_rekey(privkey_a, privkey_eph),
                encrypt(pubkey_b, privkey_eph))

    def noninteractive_reencrypt(rk, ciphertext_a):
        return (interactive_reencrypt(rk[0], ciphertext_a),
                rk[1])

    def decrypt_reencrypted(privkey_b, ciphertext_re):
        ciphertext_e, encrypted_eph = ciphertext_re
        priv_eph = decrypt(privkey_b, encrypted_eph)
        return decrypt(privkey_eph, ciphertext_e)

Of course, this can be combined with what was described above regarding hybrid encryption and the ECIES scheme.
Implementation of re-encryption for ECIES scheme can be found on our github, we call this scheme [Umbral]_.

.. [Umbral] https://github.com/nucypher/nucypher-pre-python/blob/master/npre/umbral.py

Split-key re-encryption
--------------------------
So far we've trusted one Ursula to re-encrypt data.
While Ursula cannot decrypt anything, she is responsible for revocation, applying time-based and payment conditions.
It is clear that a malicious Ursula can misapply these conditions.

In order to mitigate this risk, we make a split-key threshold (m-of-n) re-encryption.
Conceptually, it works in the following manner::

    # Alice's side
    ciphertext_alice = encrypt(pubkey_enc_a, data)
    kFrags = split_rekey(privkey_enc_a, pubkey_enc_b, m, n)

    # kFrags are given to n Ursulas

    # Ursulas' side
    for ursula in range(m):  # or any number between m and n
        ciphertext_frags_bob[i] = reencrypt(kFrags[ursula], ciphertext_alice)

    # Bob's side
    ciphertext_bob = combine(ciphertext_frags_bob)
    data = decrypt(privkey_enc_b, ciphertext_bob)

We need to find at least ``m`` Ursulas out of ``n`` who have ``kFrags`` (re-encryption key fragments) in order to make the text decryptable by Bob.
We also call fragments which Bob combines to get ``ciphertext_bob`` *cFrags*.

Digital signatures
--------------------
Sometimes network participants need to prove themselves in order to behave correctly.
This can be Ursula who puts up her stake, Alice who wants to prove Bob that it's her who created data.
For digital signing, we use ECDSA, using *secp256k1* curve, similar to what Ethereum and Bitcoin use.
Each participants has a signing keypair ``privkey_sig / pubkey_sig`` which coincides with an Ethereum address associated with this participant.

Network discovery
====================
Policy IDs
------------
Each re-encryption key fragment ``kFrag`` has a *policy* associated with it.
We call the group corresponding holding all the key fragments generated in one split-key re-encryption a *policy group*.

Each policy group has a ``policy_group_id``, generated deterministically for Alice, Bob and the shared path::

    h = hash(pubkey_sig_alice + pubkey_sig_bob + subpath)
    policy_group_id = hash(pubkey_sig_alice + h) + h

The id ``policy_group_id`` is seemingly random (which is important for protocols like Kademlia), but knowing Alice's public key Ursula can determine that Alice
is allowed to create this ID.
If Alice can sign her request and Ursula can reconstruct the first half of ``policy_group_id`` using Alice's public key and the second half, Alice can indeed
create this policy.
This way, nobody else can claim Alice's place w/o revealing much information to the public in clear.
It should be noted, however, that this doesn't suffice for a truly anonymous protocol as long as it is possible to iterate over all the public keys in the
system to figure out which policy group belongs to which pair of participants.

The ID of policies ``policy_id`` are generated as::

    h = random()
    policy_id = hash(pubkey_sig_alice + h) + h

Ursula can still check if ``policy_id`` belongs to Alice, but it's posible to keep it completely random rather than connected to Alice's public key if an
anonymous protocol is needed.

Finding Ursulas. Treasure map
---------------------------------
When Alice wants to permit Bob to read something, she first creates a bunch of ``kFrags``.
She generates ``policy_group_id`` for all of them together, and ``policy_id`` for each.

She finds ``n`` Ursulas who agree to store ``kFrags`` for long enough, and it is still within their quotas.
With each, she stores a kFrag in her key-value store ``{policy_id -> kFrag}``.

Then, she encrypts a list of all Ursulas who ended up storing kFrags using Bob's public key.
She stores this whole list in a Kademlia DHT [Kademlia]_.
This list is called *treasure map*.
Importantly, the treasure map is allowed to be replicated and migrated to different nodes, while ``kFrags`` stay with the Ursulas they were assigned to all the
time.

The whole protocol in brief::

    h = hash(pubkey_sig_alice + pubkey_sig_bob + subpath)
    policy_group_id = hash(pubkey_sig_alice + h) + h

    ursulas = find_random_ursulas(n)
    for ursula in ursulas:
        policy_id = generate_policy_id()
        ursula[policy_id] = kFrag

    treasure_map = encrypt(pubkey_enc_bob, {policy_id -> ursula for ursula in ursulas})
    # we may want to store treasure_map signed by Alice
    kademlia[policy_group_id] = treasure_map

The nodes who host ``policy_group_id`` could be same Ursulas or any other public side-channel (not a DHT in that case).
A potential flaw of this protocol (and Kademlia in particular) would be a possibility that someone spins up multiple nodes deliberately close to a chosen
``policy_group_id`` (since it's possible to calculate it for particular Alice, Bob and subpath).
In order to become Ursulas, it is required to stake a significant amount of coins, so it wouldn't necessarily be cheap to knock down a particular
``policy_group_id``.
We note that this problem exists even for Kademlia DHT used for BitTorrent protocol.

.. [Kademlia] https://en.wikipedia.org/wiki/Kademlia

Bob talking to Ursulas
------------------------
When Bob wants to use the policy, he first derives ``policy_group_id`` himself.
He then finds the treasure map and decrypts it.
From the result of decryption, he knows which Ursulas have the kFrags.
He connects to those Ursulas and asks them to re-encrypt encrypted symmetric keys he has found for the file of interest.

Becoming an Ursula
--------------------
In order to prevent the problem of creating Ursulas deliberately close to a ``policy_group_id``, we can make a special ceremony for becoming an Ursula.
Ursulas can put up their stake, and a smart contract awards an Ursula with the highest stake in the round a pseudorandom ID (rather than an ID calculated from
Ursula's public key).
Ursula commits her stake to be up and working for at least certain time.
This way, becoming an Ursula is not a trivial endeavour, and one cannot simply spin up a thousand Ursulas close to some ``policy_group_id`` which he wants to
maliciously knock off by making treasure map undiscoverable.

Correctness of re-encryption
==============================
By just looking at the result of Ursula's re-encryption, a third party cannot figure out if it was correct or not.
Thus, Alice pre-creates a bunch of re-encryptions for each Ursula to be challenged.
We call it Challenge Pack.
It is kept available to Bob and encrypted for Bob.
The idea is that sometimes Bob can challenge Ursula with ciphertexts which do not contain any useful information but exist solely to show an evidence that
Ursula is misbehaving if this starts happening.

Agreement. Challenge pack
---------------------
When Ursula gets in agreement with Alice, she publishes::

    hash(kFrag), pubkey_sig_ursula, pubkey-sig_alice, sign(alice, hash(kFrag))

Ursula should confirm (publicly)::

    sign(ursula, hash(kFrag))

When Alice creates the policy, she pre-creates challenge *cFrags* in the following manner::

    challenge_pack = defaultdict(list)
    for kFrag in kFrags:
        for _ in range(n_challenges):
            challenge = secure_random()
            ch_cfrag = reencrypt(kFrag, challenge)
            ch_h = hash(kFrag)
            challenge_pack[kFrag].append(
                (challenge, ch_cfrag),
                sign(alice, ch_h + challenge),
                sign(alice, ch_h + challenge + ch_cfrag))

The challenge pack gets encrypted for Bob using ``pubkey_enc_bob`` and stored in a DHT, just like the treasure map was stored.

At any time, Bob can report misbehaving nodes using the challenge pack protocol. After successfully reporting, Bob gets rewarded if Ursula was caught not
re-encrypting properly.

Possible misbehavior modes:

* Ursula not being online for re-encryption;
* Ursula returning false results;
* Alice producing the wrong challenge pack intentionally, in order to frame Ursula as guilty;
* Bob trying to spam Ursula(s) in order to damage the system's availability (alternatively, EvilBob trying to make Ursulas who handle Bob's kFrags unavailable).

Ursula's misbehavior can be caused by Ursula forgetting the kFrag, refusing to operate (because she doesn't like Bob) or Ursula simply going offline.

Challenge protocol
------------------------
If Bob decides that Ursula could be misbehaving, he unseals the challenge pack.
He gets the ``challenge``, the expected result ``ch_cfrag`` and their signatures by randomly selecting from the list.

Bob challenges Ursula with a value from challenge pack::

    Ursula, decrypt this: challenge

If Ursula doesn't respond in time, Bob publishes the input string (signed by Alice) to the smart contact (or oracles)::

    Alert, Ursula didn't decrypt: challenge, ch_cfrag, sig(alice, ch_h + challenge), alice_pubkey

If Ursula doesn't respond in the next few blocks, she gets penalized after some specified number of blocks.

If Ursula responds but it's garbage, we get to the next point; if it's not garbage - her stake doesn't get seized. In any case, Ursula says::

    challenge, reencrypt(challenge), ch_h, sig(ursula, hash(challenge + reencrypt(challenge) + ch_h)), ursula_pubkey

If Ursula returns garbage, Bob published both Ursula's response (signed by Ursula) and the input challenge (signed by Alice) to the smart contract (or if Bob
doesn't do that, Ursula was ok and continue)::

    Guys, Ursula got the wrong result! challenge, ch_cfrag, ch_h, sig(alice, ch_h + challenge + ch_cfrag)

Smart contract can verify that Ursula's response is not the same as the challenge pack response (e.g. ``ch_cfrag != reencrypt(challenge)``).
The proxy re-encryption algorithm we have for ECIES allows Ursula to verify that Alice gave her a working re-encryption key.
So when Ursula came to the agreement, she had an opportunity to check.

If Ursula ended up being penalized, Bob gets the seized collateral.

Centralized stub to mock trustless functionality
=================================================

Seizing collateral, as well as discovering treasure map and challenge pack, requires rigorous testing.
Thus, we will launch a temporary centralized service which will be replacing pieces of decentralized functionality until it's implemented in a decentralized
way.
We should note that re-encryption keys will still be handled by multiple network participants.
The proposed centralized service just mitigates risks of participants refusing to behave correctly until the Solidity code which enforces all the conditions is
thoroughly tested.

Conclusion
============
We described the first version of the decentralized key management system NuCypher KMS.
It does enforce correctness of operation, but it yet doesn't disinsentivize leaking ``kFrags``.
Neither does it focuses on anonymity of re-encryption.
This will be the goal for future releases.
