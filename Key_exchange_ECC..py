import numpy as np
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import ec

alice_private_key = ec.generate_private_key(ec.SECP256R1())
bob_private_key = ec.generate_private_key(ec.SECP256R1())  # Same curve

alice_public_key = alice_private_key.public_key()
bob_public_key = bob_private_key.public_key()

alice_shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)
bob_shared_key = bob_private_key.exchange(ec.ECDH(), alice_public_key)

assert alice_shared_key == bob_shared_key, "Key exchange failed!"

alice_curve = alice_private_key.public_key().curve.name
bob_curve = bob_private_key.public_key().curve.name

print(f"Alice is using curve: {alice_curve}")
print(f"Bob is using curve: {bob_curve}")
print("Shared key established:", alice_shared_key.hex())


p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF  
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B  

x_vals = np.linspace(-3, 3, 400)  

y2_vals = x_vals**3 + a * x_vals + b

valid_x, valid_y = [], []

for x, y2 in zip(x_vals, y2_vals):
    if y2 >= 0:  
        y = np.sqrt(y2)
        valid_x.append(x)
        valid_y.append(y)

plt.figure(figsize=(10, 6))
plt.scatter(valid_x, valid_y, color="blue", s=2, label="Curve Points")
plt.scatter(valid_x, [-y for y in valid_y], color="blue", s=2)  # Mirror points
plt.title(f"Elliptic Curve {alice_curve}")
plt.xlabel("x")
plt.ylabel("y")
plt.legend()
plt.grid()
plt.show()
