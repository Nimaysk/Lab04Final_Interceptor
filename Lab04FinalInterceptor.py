# Lab04Final -- Part 3: The Stateful Interceptor
# DH key exchange + a rollback-resistant PRNG stream cipher
# + Mallory as an active man-in-the-middle.

import hashlib
import secrets
import os


# ---------------------------------------------------------------------
# UI HELPER FUNCTIONS
# ---------------------------------------------------------------------

def print_header(text):
    print(f"\n{'=' * 60}")
    print(text)
    print("=" * 60)


def print_step(text):
    print(f"\n>> {text}")


def print_info(label, value):
    print(f"   [{label}]: {str(value)[:70]}...")


# ---------------------------------------------------------------------
# DIFFIE-HELLMAN PARAMETERS
# ---------------------------------------------------------------------

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)

G = 2


# ---------------------------------------------------------------------
# PART A: STATEFUL ROLLBACK-RESISTANT PRNG
# ---------------------------------------------------------------------

class SecurePRNG:

    def __init__(self, seed_int):
        """
        Initialize the PRNG from the Diffie-Hellman shared secret.

        SHA-256 converts the shared secret into a fixed 32-byte state.
        """
        seed_bytes = str(seed_int).encode("utf-8")
        self.state = hashlib.sha256(seed_bytes).digest()

    def generate(self, n_bytes):
        """
        Produce n_bytes of pseudorandom output.

        After producing every block, the internal state advances through
        a one-way hash. The previous state is discarded.
        """
        output = b""

        while len(output) < n_bytes:
            # Produce a keystream block from the current state.
            block = hashlib.sha256(
                self.state + b"output"
            ).digest()

            # Immediately advance the internal state.
            self.state = hashlib.sha256(
                self.state + b"update"
            ).digest()

            output += block

        return output[:n_bytes]


def xor_crypt(data, prng):
    """
    Encrypt or decrypt data using XOR with a generated keystream.

    XOR encryption and decryption use the same operation.
    """
    keystream = prng.generate(len(data))

    return bytes(
        data_byte ^ key_byte
        for data_byte, key_byte in zip(data, keystream)
    )


# ---------------------------------------------------------------------
# PART B: ALICE AND BOB
# ---------------------------------------------------------------------

class Entity:

    def __init__(self, name):
        self.name = name

        # Generate a private DH exponent and its corresponding public key.
        self.private_key = secrets.randbelow(P - 3) + 2
        self.public_key = pow(G, self.private_key, P)

        self.session_prng = None

    def get_public_hex(self):
        return hex(self.public_key)

    def establish_session(self, partner_pub_hex):
        """
        Calculate the DH shared secret and use it to initialize the PRNG.
        """
        partner_pub = int(partner_pub_hex, 16)

        # Basic validation prevents obviously invalid public values.
        if partner_pub <= 1 or partner_pub >= P - 1:
            raise ValueError("Invalid Diffie-Hellman public key.")

        shared_secret = pow(
            partner_pub,
            self.private_key,
            P
        )

        self.session_prng = SecurePRNG(shared_secret)


# ---------------------------------------------------------------------
# NETWORK SIMULATION
# ---------------------------------------------------------------------

class Network:
    """
    Simulates the network and provides an interception hook for Mallory.
    """

    def __init__(self):
        self.mallory = None

    def send(self, sender, recipient, payload):
        print(
            f"[NET] {sender} -> {recipient}: "
            f"{str(payload)[:60]}..."
        )

        if self.mallory:
            return self.mallory.intercept(
                sender,
                recipient,
                payload
            )

        return payload


# ---------------------------------------------------------------------
# PART C: MALLORY'S MAN-IN-THE-MIDDLE PROXY
# ---------------------------------------------------------------------

class Mallory:

    def __init__(self):
        # Mallory creates her own DH private and public keys.
        self.private_key = secrets.randbelow(P - 3) + 2
        self.public_hex = hex(
            pow(G, self.private_key, P)
        )

        # Mallory maintains one synchronized session with Alice
        # and a separate synchronized session with Bob.
        self.alice_prng = None
        self.bob_prng = None

    def intercept(self, sender, recipient, payload):

        # -------------------------------------------------------------
        # Intercept the Diffie-Hellman public-key exchange.
        # -------------------------------------------------------------

        if isinstance(payload, str) and payload.startswith("0x"):
            remote_pub = int(payload, 16)

            my_shared_secret = pow(
                remote_pub,
                self.private_key,
                P
            )

            if sender == "Alice":
                self.alice_prng = SecurePRNG(
                    my_shared_secret
                )

                print(
                    "[MALLORY] Captured Alice's public key "
                    "and created an Alice-Mallory session."
                )

            elif sender == "Bob":
                self.bob_prng = SecurePRNG(
                    my_shared_secret
                )

                print(
                    "[MALLORY] Captured Bob's public key "
                    "and created a Bob-Mallory session."
                )

            print(
                "[MALLORY] Replacing the sender's public key "
                "with Mallory's public key."
            )

            # Alice and Bob receive Mallory's key instead of each
            # other's authentic public key.
            return self.public_hex

        # -------------------------------------------------------------
        # Intercept an encrypted message.
        # -------------------------------------------------------------

        if isinstance(payload, bytes):
            print(
                f"[MALLORY] Intercepting encrypted message "
                f"from {sender}..."
            )

            if sender == "Alice":
                sender_prng = self.alice_prng
                recipient_prng = self.bob_prng
            else:
                sender_prng = self.bob_prng
                recipient_prng = self.alice_prng

            if sender_prng is None or recipient_prng is None:
                raise RuntimeError(
                    "Mallory's sessions have not been established."
                )

            # Decrypt using Mallory's synchronized session
            # with the sender.
            plaintext = xor_crypt(
                payload,
                sender_prng
            )

            print(
                "[MALLORY] Original message:",
                plaintext.decode("utf-8")
            )

            # Change one part of the message.
            modified_plaintext = plaintext.replace(
                b"9pm",
                b"3am"
            )

            print(
                "[MALLORY] Modified message:",
                modified_plaintext.decode("utf-8")
            )

            # Re-encrypt using Mallory's synchronized session
            # with the intended recipient.
            modified_ciphertext = xor_crypt(
                modified_plaintext,
                recipient_prng
            )

            print(
                "[MALLORY] Re-encrypted the modified message "
                "for the recipient."
            )

            return modified_ciphertext

        return payload


# ---------------------------------------------------------------------
# MAIN EXECUTION SIMULATION
# ---------------------------------------------------------------------

def main():

    # ================================================================
    # SCENARIO A: BENIGN COMMUNICATION
    # ================================================================

    print_header(
        "SCENARIO A: BENIGN (SECURE) COMMUNICATION"
    )

    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()

    print_step("Step 0: Global Group Parameters")
    print_info("G (Generator)", G)
    print_info("P (Prime)", P)

    print_step("Step 1: Public Key Exchange")
    print_info("Alice Private (a)", alice.private_key)
    print_info("Bob Private (b)", bob.private_key)

    # Alice sends her authentic public key to Bob.
    alice_pub = alice.get_public_hex()
    print_info(
        "Alice Public (A = G^a mod P)",
        alice_pub
    )

    key_for_bob = net.send(
        "Alice",
        "Bob",
        alice_pub
    )

    # Bob sends his authentic public key to Alice.
    bob_pub = bob.get_public_hex()
    print_info(
        "Bob Public (B = G^b mod P)",
        bob_pub
    )

    key_for_alice = net.send(
        "Bob",
        "Alice",
        bob_pub
    )

    print_step("Step 2: Establishing Sessions")

    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)

    print(
        "   [Status]: Shared secret computed: "
        "S = B^a mod P = A^b mod P"
    )

    print_step("Step 3: Secure Message Transmission")

    message = (
        b"Nimay Sathiskumar 801291732 says hello to Bob."
    )

    print(
        "   [Alice original]:",
        message.decode("utf-8")
    )

    encrypted_msg = xor_crypt(
        message,
        alice.session_prng
    )

    print_info(
        "Encrypted message",
        encrypted_msg.hex()
    )

    delivered_data = net.send(
        "Alice",
        "Bob",
        encrypted_msg
    )

    final_message = xor_crypt(
        delivered_data,
        bob.session_prng
    )

    print(
        "   [Bob decrypted]:",
        final_message.decode("utf-8")
    )

    if final_message == message:
        print(
            "\n[SUCCESS] SCENARIO A: "
            "Bob recovered Alice's original message intact."
        )
    else:
        print(
            "\n[ERROR] SCENARIO A: "
            "Bob did not recover the original message."
        )

    # ================================================================
    # SCENARIO B: MALLORY'S MITM ATTACK
    # ================================================================

    print_header(
        "SCENARIO B: MALICIOUS (MITM) ATTACK"
    )

    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()

    net = Network()
    net.mallory = mallory

    print_step("Step 1: Mallory's Parameters")
    print_info(
        "Mallory Private (m)",
        mallory.private_key
    )
    print_info(
        "Mallory Public (M)",
        mallory.public_hex
    )

    print_step("Step 2: Compromised Key Exchange")

    print("Alice sending key to Bob...")

    key_for_bob = net.send(
        "Alice",
        "Bob",
        alice.get_public_hex()
    )

    print("Bob sending key to Alice...")

    key_for_alice = net.send(
        "Bob",
        "Alice",
        bob.get_public_hex()
    )

    print_step("Step 3: Poisoned Shared Secrets")

    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)

    print(
        "   [Alice Session]: "
        "S_am = (Mallory_Pub)^a mod P"
    )
    print(
        "   [Bob Session]:   "
        "S_bm = (Mallory_Pub)^b mod P"
    )

    print_step("Step 4: Interception")

    message = b"Meet me at 9pm."

    print(
        "   [Alice original]:",
        message.decode("utf-8")
    )

    encrypted_msg = xor_crypt(
        message,
        alice.session_prng
    )

    delivered_data = net.send(
        "Alice",
        "Bob",
        encrypted_msg
    )

    final_message = xor_crypt(
        delivered_data,
        bob.session_prng
    )

    print(
        "   [Bob received]:",
        final_message.decode("utf-8")
    )

    if b"3am" in final_message:
        print(
            "\n[DANGER] MITM SUCCESS: "
            "Mallory used her private key to decrypt, "
            "modify, and re-encrypt the message."
        )
    else:
        print(
            "\n[ERROR] MITM modification was not successful."
        )


if __name__ == "__main__":
    main()