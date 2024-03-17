import hashlib

def hash_text():
    text = input("Enter the text to hash: ")

    # Hash using MD5
    md5_hash = hashlib.md5(text.encode()).hexdigest()
    print(f"MD5 Hash: {md5_hash}")

    # Hash using SHA-1
    sha1_hash = hashlib.sha1(text.encode()).hexdigest()
    print(f"SHA-1 Hash: {sha1_hash}")

    # Hash using SHA-256
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    print(f"SHA-256 Hash: {sha256_hash}")

    # Hash using SHA-384
    sha384_hash = hashlib.sha384(text.encode()).hexdigest()
    print(f"SHA-384 Hash: {sha384_hash}")

    # Hash using SHA-512
    sha512_hash = hashlib.sha512(text.encode()).hexdigest()
    print(f"SHA-512 Hash: {sha512_hash}")

# Example usage
hash_text()
