# Akasec_Bootcamp : Cryptography Challenge 👨🏻‍💻

### function :
```
import random
from pwn import xor

random.seed(random.randint(1, 1000))

KEY = random.randbytes(16)
FLAG = b'AKASEC{example_flag}'

print(xor(KEY, FLAG).hex())
```

### output of function :
```
dc20e2000be9200c7949e47cef836da1ae05c73811cb375e7049e95e
```

### solution : 
```
from pwn import xor
import random

ciphertext = bytes.fromhex('dc20e2000be9200c7949e47cef836da1ae05c73811cb375e7049e95e')

def decrypt_with_seed(seed):
    random.seed(seed)  # Set the seed
    KEY = random.randbytes(16)  # Generate the key
    return xor(KEY, ciphertext)  # Decrypt the ciphertext


for seed in range(1, 1001):
    decrypted = decrypt_with_seed(seed)
    decrypted_flag = decrypted.decode(errors='ignore')  # Decode and ignore errors
    print(f"Seed {seed}: {decrypted_flag}")  # Output the decrypted result
    if decrypted_flag.startswith('AKASEC{'):
        print(f"Found the complete flag: {decrypted_flag}")
        break
```

## flag : AKASEC{ahya_xni_3ndk_al3ayl} 
