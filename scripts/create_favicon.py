#!/usr/bin/env python3
"""
Script to convert logo.png to favicon.ico
Creates favicon in multiple formats for better browser compatibility
"""

from PIL import Image
import os

def create_favicon():
    # Source logo
    logo_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'uploads', 'logo.png')
    
    # Output paths
    static_dir = os.path.join(os.path.dirname(__file__), '..', 'static')
    favicon_ico = os.path.join(static_dir, 'favicon.ico')
    favicon_png = os.path.join(static_dir, 'favicon.png')
    
    # Check if source exists
    if not os.path.exists(logo_path):
        print(f"Error: Logo not found at {logo_path}")
        return False
    
    try:
        # Open the logo image
        logo = Image.open(logo_path)
        print(f"Original logo size: {logo.size}")
        
        # Convert to RGBA if needed
        if logo.mode != 'RGBA':
            logo = logo.convert('RGBA')
        
        # Create favicon.ico (standard 32x32 favicon)
        favicon_sizes = [(32, 32), (16, 16)]
        favicon_img = Image.new('RGBA', (32, 32), (255, 255, 255, 0))
        
        # Resize logo to 32x32 for main favicon
        logo_resized = logo.copy()
        logo_resized.thumbnail((32, 32), Image.Resampling.LANCZOS)
        
        # Paste resized logo in the center
        offset = ((32 - logo_resized.width) // 2, (32 - logo_resized.height) // 2)
        favicon_img.paste(logo_resized, offset, logo_resized)
        
        # Save as ICO format
        favicon_img.save(favicon_ico, format='ICO', sizes=[(32, 32), (16, 16)])
        print(f"✓ Created favicon.ico: {favicon_ico}")
        
        # Also save as PNG for modern browsers (32x32)
        favicon_img.save(favicon_png)
        print(f"✓ Created favicon.png: {favicon_png}")
        
        # Create a duplicate in uploads folder for backup
        favicon_uploads = os.path.join(os.path.dirname(__file__), '..', 'static', 'uploads', 'favicon.png')
        favicon_img.save(favicon_uploads)
        print(f"✓ Created backup favicon in uploads: {favicon_uploads}")
        
        print("\nFavicon created successfully!")
        print(f"  - favicon.ico (use in <link rel='icon'>)")
        print(f"  - favicon.png (modern browser support)")
        print(f"  - uploads/favicon.png (backup copy)")
        
        return True
        
    except Exception as e:
        print(f"Error creating favicon: {e}")
        return False

if __name__ == '__main__':
    create_favicon()
