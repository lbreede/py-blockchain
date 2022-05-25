from datetime import datetime
from random import random
import json
import hashlib
import logging

DIFFICULTY = 4

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    # datefmt="%d-%b-%y %H:%M:%S",
    level=logging.INFO,
)


class Transaction:
    def __init__(self, amount, sender, receiver):
        self.amount = amount
        self.sender = sender
        self.receiver = receiver

    def to_string(self):
        return json.dumps(vars(self), separators=(",", ":"))

    def shorten(self, string):
        return string[:4] + "..." + string[-4:]

    def prettify(self):
        sender = "0x" + self.shorten(self.sender)
        receiver = "0x" + self.shorten(self.receiver)
        return f"[{sender}] sends ${self.amount} to [{receiver}]"

    def pretty_print(self):
        print(self.prettify())


class Block:
    def __init__(self, prev_hash, transaction, nonce=None):
        self.transaction = transaction
        self.prev_hash = prev_hash
        self.timestamp = datetime.now()
        # self.nonce = round(random() * 999999999)
        self.nonce = nonce

    @property
    def hash(self):
        header = (
            str(self.transaction.to_string())
            + str(self.prev_hash)
            + str(self.timestamp)
            + str(self.nonce)
        )
        return hashlib.sha256(header.encode()).hexdigest()

    # def shorten(self, string):
    #     return string[:4] + "..." + string[-4:]

    def prettify(self):
        curr_hash = "0x" + self.hash
        prev_hash = "0x" + self.prev_hash
        transaction = self.transaction.prettify()
        return (
            f"=== Block #{{}} {'='*73}\n"
            f"Hash:          [{curr_hash}]\n"
            f"Previous Hash: [{prev_hash}]\n"
            f"Transaction:   {transaction}\n"
            f"Timestamp:     {self.timestamp}\n"
            f"Nonce:         {self.nonce}\n\n\n"
        )


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Chain(metaclass=Singleton):
    def __init__(self):
        self.chain = [Block("0", Transaction(100, "GENESIS", "SATOSHI"))]

    @property
    def last_block(self):
        return self.chain[-1]

    def mine(self, nonce, difficulty=4):
        solution = 0
        logging.info("⛏ Mining...")

        while True:
            attempt = hashlib.md5(str(nonce + solution).encode()).hexdigest()

            if attempt[:difficulty] == "0" * difficulty:
                logging.info(f"✅ Solved: {solution}")
                return solution
            solution += 1

    def verify_transaction(
        self, transaction, sender_public_key, signature, verification
    ):
        string = transaction.to_string() + signature + sender_public_key
        return hashlib.sha256(string.encode()).hexdigest() == verification

    def add_block(self, transaction, sender_public_key, signature, verification):
        is_valid = self.verify_transaction(
            transaction, sender_public_key, signature, verification
        )
        if is_valid:

            # new_block = Block(self.last_block.hash, transaction)
            # self.mine(new_block.nonce, difficulty=4)

            # define nonce here, then mine, then create new block with nonce as arg
            # this is so the timestamp reflects the time after mining, not before
            nonce = round(random() * 999999999)
            self.mine(nonce, difficulty=DIFFICULTY)
            new_block = Block(self.last_block.hash, transaction, nonce)

            self.chain.append(new_block)

    def verify_chain(self):
        verifications = []
        for i, block in enumerate(self.chain):
            if i > 0:
                prev_block = self.chain[i - 1]
                if block.prev_hash != prev_block.hash:
                    logging.warning(
                        f"Chain has been compromised between Block {i-1} and {i}"
                    )
                    return False

        logging.info("Chain integrity confirmed!")
        return True

    def prettify(self):
        pretty = ""
        for i, block in enumerate(self.chain):
            pretty += block.prettify().format(str(i).zfill(3))
        return pretty

    def pretty_print(self):
        print(self.prettify())

    def pretty_log(self):
        with open("blockchain.log", "w") as f:
            f.write(self.prettify())


class Wallet:
    def __init__(self):
        # not great.. but good enough
        self.public_key = hashlib.sha256(str(datetime.now()).encode()).hexdigest()
        self.private_key = hashlib.sha256(str(datetime.now()).encode()).hexdigest()

    def sign(self, transaction):
        string = transaction.to_string() + self.private_key
        signature = hashlib.sha256(string.encode()).hexdigest()
        verification = self.verify(transaction, signature)
        return signature, verification

    def verify(self, transaction, signature):
        string = transaction.to_string() + signature + self.public_key
        return hashlib.sha256(string.encode()).hexdigest()

    def send_money(self, amount, receiver_public_key):
        transaction = Transaction(amount, self.public_key, receiver_public_key)
        signature, verification = self.sign(transaction)
        Chain().add_block(transaction, self.public_key, signature, verification)


def make_fake_transactions(n):
    for i in range(n):
        amount = round(random() * 100)
        Wallet().send_money(amount, Wallet().public_key)

        if random() < 0.1:
            new_amount = round(random() * 10000)
            Chain().chain[i // 2].transaction.amount = new_amount

        Chain().verify_chain()


def main():
    blockchain = Chain()
    blockchain.verify_chain()

    satoshi = Wallet()
    bob = Wallet()
    alice = Wallet()

    make_fake_transactions(100)

    blockchain.pretty_log()


if __name__ == "__main__":
    main()
