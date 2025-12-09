import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import os

def generate_vapid_keys():
    """Generate VAPID public and private keys for Web Push notifications"""
    
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key
    private_key_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
    private_key_base64 = base64.urlsafe_b64encode(private_key_bytes).decode('utf-8').strip('=')
    
    # Serialize public key
    public_key_bytes = public_key.public_numbers().x.to_bytes(32, 'big') + public_key.public_numbers().y.to_bytes(32, 'big')
    public_key_base64 = base64.urlsafe_b64encode(public_key_bytes).decode('utf-8').strip('=')
    
    return {
        "public_key": public_key_base64,
        "private_key": private_key_base64
    }

def print_vapid_keys():
    """Generate and display VAPID keys in terminal"""
    
    print("=" * 60)
    print("VAPID KEYS GENERATOR FOR WEB PUSH NOTIFICATIONS")
    print("=" * 60)
    print("\nGenerating VAPID keys...\n")
    
    keys = generate_vapid_keys()
    
    print("✅ PUBLIC KEY:")
    print("-" * 40)
    print(keys["public_key"])
    print()
    
    print("🔒 PRIVATE KEY:")
    print("-" * 40)
    print(keys["private_key"])
    print()
    
    print("📋 HOW TO USE:")
    print("-" * 40)
    print("1. Add these to your .env file:")
    print(f'   VAPID_PUBLIC_KEY="{keys["public_key"]}"')
    print(f'   VAPID_PRIVATE_KEY="{keys["private_key"]}"')
    print()
    print("2. In Flask config:")
    print(f'   app.config["VAPID_PUBLIC_KEY"] = "{keys["public_key"]}"')
    print(f'   app.config["VAPID_PRIVATE_KEY"] = "{keys["private_key"]}"')
    print()
    print("3. Email (optional, but recommended):")
    print('   VAPID_CLAIM_EMAIL="your-email@example.com"')
    print()
    print("=" * 60)
    print("⚠️  IMPORTANT: Keep private key secret and never commit to git!")
    print("=" * 60)
    
    return keys

if __name__ == "__main__":
    print_vapid_keys()