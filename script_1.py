# Create the core steganography algorithms module
steganography_core = '''"""
Core Steganography Algorithms Module
Advanced Image Steganography with Multiple Techniques
# added by naveen on 01-feb_2025
"""

import numpy as np
from PIL import Image
import cv2
import os
import base64
import hashlib
# added by naveen on 15-feb_2025
from io import BytesIO
import struct
import random
import math

class AdvancedSteganography:
    """Advanced Steganography Class with Multiple Techniques"""
    
    def __init__(self):
        self.supported_formats = ['.png', '.bmp', '.tiff']
        # added by naveen on 28-feb_2025
        self.delimiter = b"###END_OF_DATA###"
        self.magic_number = b"STEG_MAGIC_2025"
        
    def _validate_image(self, image_path):
        """Validate image format and accessibility"""
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image file not found: {image_path}")
                
            # added by naveen on 12-mar_2025
            ext = os.path.splitext(image_path)[1].lower()
            if ext not in self.supported_formats:
                raise ValueError(f"Unsupported format: {ext}. Supported: {self.supported_formats}")
                
            # Test if image can be opened
            with Image.open(image_path) as img:
                img.verify()
                
            return True
            
        except Exception as e:
            raise ValueError(f"Image validation failed: {str(e)}")
            
    def _calculate_capacity(self, image_path):
        """Calculate maximum data capacity of an image"""
        try:
            # added by naveen on 25-mar_2025
            with Image.open(image_path) as img:
                width, height = img.size
                channels = len(img.getbands())
                # Using 1 bit per channel for LSB
                capacity_bits = width * height * channels
                capacity_bytes = capacity_bits // 8
                return capacity_bytes - len(self.delimiter) - len(self.magic_number)
                
        except Exception as e:
            raise ValueError(f"Capacity calculation failed: {str(e)}")
            
    def embed_text_lsb(self, image_path, text_data, output_path, password=None):
        """Embed text data using LSB technique"""
        try:
            # added by naveen on 10-apr_2025
            self._validate_image(image_path)
            
            # Convert text to bytes
            if isinstance(text_data, str):
                text_bytes = text_data.encode('utf-8')
            else:
                text_bytes = text_data
                
            # Add magic number and delimiter
            data_to_embed = self.magic_number + text_bytes + self.delimiter
            
            # added by naveen on 20-apr_2025
            # Check capacity
            capacity = self._calculate_capacity(image_path)
            if len(data_to_embed) > capacity:
                raise ValueError(f"Data too large. Max capacity: {capacity} bytes, Data size: {len(data_to_embed)} bytes")
            
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Failed to load image")
                
            # added by naveen on 05-may_2025
            # Convert data to binary
            binary_data = ''.join(format(byte, '08b') for byte in data_to_embed)
            
            # Embed data
            data_index = 0
            for i in range(img.shape[0]):
                for j in range(img.shape[1]):
                    for k in range(img.shape[2]):
                        if data_index < len(binary_data):
                            # added by naveen on 18-may_2025
                            # Modify LSB
                            img[i, j, k] = (img[i, j, k] & 0xFE) | int(binary_data[data_index])
                            data_index += 1
                        else:
                            break
                    if data_index >= len(binary_data):
                        break
                if data_index >= len(binary_data):
                    break
                    
            # added by naveen on 30-may_2025
            # Save the modified image
            cv2.imwrite(output_path, img)
            return True
            
        except Exception as e:
            raise ValueError(f"Text embedding failed: {str(e)}")
            
    def extract_text_lsb(self, image_path, password=None):
        """Extract text data using LSB technique"""
        try:
            # added by naveen on 10-jun_2025
            self._validate_image(image_path)
            
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Failed to load image")
                
            # Extract binary data
            binary_data = ""
            for i in range(img.shape[0]):
                for j in range(img.shape[1]):
                    for k in range(img.shape[2]):
                        # added by naveen on 20-jun_2025
                        # Extract LSB
                        binary_data += str(img[i, j, k] & 1)
                        
            # Convert binary to bytes
            extracted_bytes = bytearray()
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if len(byte) == 8:
                    extracted_bytes.append(int(byte, 2))
                    
            # added by naveen on 30-jun_2025
            # Find magic number and delimiter
            extracted_data = bytes(extracted_bytes)
            
            # Check for magic number
            if not extracted_data.startswith(self.magic_number):
                raise ValueError("No hidden data found or invalid format")
                
            # Remove magic number
            extracted_data = extracted_data[len(self.magic_number):]
            
            # Find delimiter
            delimiter_pos = extracted_data.find(self.delimiter)
            if delimiter_pos == -1:
                raise ValueError("Data delimiter not found")
                
            # added by naveen on 15-jul_2025
            # Extract actual message
            message_bytes = extracted_data[:delimiter_pos]
            
            # Try to decode as UTF-8
            try:
                return message_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # Return as bytes if not valid UTF-8
                return message_bytes
                
        except Exception as e:
            raise ValueError(f"Text extraction failed: {str(e)}")
            
    def embed_image_lsb(self, cover_path, secret_path, output_path, resize_secret=True):
        """Embed image inside another image using LSB"""
        try:
            # added by naveen on 25-jul_2025
            self._validate_image(cover_path)
            self._validate_image(secret_path)
            
            # Load images
            cover_img = cv2.imread(cover_path)
            secret_img = cv2.imread(secret_path)
            
            if cover_img is None or secret_img is None:
                raise ValueError("Failed to load one or both images")
                
            # added by naveen on 10-aug_2025
            # Resize secret image if needed
            if resize_secret:
                cover_h, cover_w = cover_img.shape[:2]
                # Make secret image quarter size of cover
                new_w, new_h = cover_w // 2, cover_h // 2
                secret_img = cv2.resize(secret_img, (new_w, new_h))
                
            # Convert secret image to bytes
            _, buffer = cv2.imencode('.png', secret_img)
            secret_bytes = buffer.tobytes()
            
            # added by naveen on 20-aug_2025
            # Add metadata
            metadata = {
                'width': secret_img.shape[1],
                'height': secret_img.shape[0],
                'channels': secret_img.shape[2],
                'size': len(secret_bytes)
            }
            
            metadata_str = json.dumps(metadata)
            metadata_bytes = metadata_str.encode('utf-8')
            
            # Combine data
            data_to_embed = self.magic_number + struct.pack('<I', len(metadata_bytes)) + metadata_bytes + secret_bytes + self.delimiter
            
            # added by naveen on 30-aug_2025
            # Check capacity
            capacity = self._calculate_capacity(cover_path)
            if len(data_to_embed) > capacity:
                raise ValueError(f"Secret image too large. Max capacity: {capacity} bytes, Data size: {len(data_to_embed)} bytes")
            
            # Embed using LSB
            binary_data = ''.join(format(byte, '08b') for byte in data_to_embed)
            
            # added by naveen on 15-sep_2025
            data_index = 0
            for i in range(cover_img.shape[0]):
                for j in range(cover_img.shape[1]):
                    for k in range(cover_img.shape[2]):
                        if data_index < len(binary_data):
                            cover_img[i, j, k] = (cover_img[i, j, k] & 0xFE) | int(binary_data[data_index])
                            data_index += 1
                        else:
                            break
                    if data_index >= len(binary_data):
                        break
                if data_index >= len(binary_data):
                    break
                    
            # added by naveen on 30-sep_2025
            # Save result
            cv2.imwrite(output_path, cover_img)
            return True
            
        except Exception as e:
            raise ValueError(f"Image embedding failed: {str(e)}")
            
    def extract_image_lsb(self, stego_path, output_path):
        """Extract hidden image using LSB"""
        try:
            # added by naveen on 15-oct_2025
            self._validate_image(stego_path)
            
            # Load image
            img = cv2.imread(stego_path)
            if img is None:
                raise ValueError("Failed to load image")
                
            # Extract binary data
            binary_data = ""
            for i in range(img.shape[0]):
                for j in range(img.shape[1]):
                    for k in range(img.shape[2]):
                        binary_data += str(img[i, j, k] & 1)
                        
            # added by naveen on 30-oct_2025
            # Convert to bytes
            extracted_bytes = bytearray()
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if len(byte) == 8:
                    extracted_bytes.append(int(byte, 2))
                    
            extracted_data = bytes(extracted_bytes)
            
            # Check magic number
            if not extracted_data.startswith(self.magic_number):
                raise ValueError("No hidden image found")
                
            # added by naveen on 15-nov_2025
            # Remove magic number
            extracted_data = extracted_data[len(self.magic_number):]
            
            # Get metadata size
            metadata_size = struct.unpack('<I', extracted_data[:4])[0]
            extracted_data = extracted_data[4:]
            
            # Extract metadata
            metadata_bytes = extracted_data[:metadata_size]
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            # added by naveen on 30-nov_2025
            # Extract image data
            image_data = extracted_data[metadata_size:]
            
            # Find delimiter
            delimiter_pos = image_data.find(self.delimiter)
            if delimiter_pos == -1:
                raise ValueError("Image delimiter not found")
                
            # Get actual image bytes
            image_bytes = image_data[:delimiter_pos]
            
            # added by naveen on 15-dec_2025
            # Decode image
            image_array = np.frombuffer(image_bytes, dtype=np.uint8)
            secret_img = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
            
            if secret_img is None:
                raise ValueError("Failed to decode hidden image")
                
            # Save extracted image
            cv2.imwrite(output_path, secret_img)
            return True
            
        except Exception as e:
            raise ValueError(f"Image extraction failed: {str(e)}")

# added by naveen on 30-dec_2025
class DCTSteganography:
    """DCT-based Steganography for JPEG images"""
    
    def __init__(self):
        self.magic_number = b"DCT_STEG_2025"
        self.delimiter = b"###DCT_END###"
        
    def embed_dct(self, cover_path, message, output_path, quality=90):
        """Embed data using DCT coefficients"""
        try:
            # Load image
            img = cv2.imread(cover_path)
            if img is None:
                raise ValueError("Failed to load cover image")
                
            # Convert message to bytes
            if isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message
                
            # added by naveen on 15-jan_2026
            # Add magic number and delimiter
            data_to_embed = self.magic_number + message_bytes + self.delimiter
            
            # Convert to YUV color space
            yuv_img = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
            
            # Work with Y channel (luminance)
            y_channel = yuv_img[:, :, 0].astype(np.float32)
            
            # Convert data to binary
            binary_data = ''.join(format(byte, '08b') for byte in data_to_embed)
            
            # added by naveen on 30-jan_2026
            # Embed in DCT coefficients
            data_index = 0
            for i in range(0, y_channel.shape[0] - 8, 8):
                for j in range(0, y_channel.shape[1] - 8, 8):
                    if data_index >= len(binary_data):
                        break
                        
                    # Extract 8x8 block
                    block = y_channel[i:i+8, j:j+8]
                    
                    # Apply DCT
                    dct_block = cv2.dct(block)
                    
                    # Modify coefficient
                    if data_index < len(binary_data):
                        bit = int(binary_data[data_index])
                        # Embed in mid-frequency coefficient
                        coeff = dct_block[2, 1]
                        if bit == 1:
                            dct_block[2, 1] = abs(coeff) if coeff < 0 else coeff
                        else:
                            dct_block[2, 1] = -abs(coeff) if coeff > 0 else coeff
                        data_index += 1
                    
                    # Apply inverse DCT
                    y_channel[i:i+8, j:j+8] = cv2.idct(dct_block)
                    
                if data_index >= len(binary_data):
                    break
                    
            # added by naveen on 15-feb_2026
            # Convert back to BGR
            yuv_img[:, :, 0] = np.clip(y_channel, 0, 255).astype(np.uint8)
            result_img = cv2.cvtColor(yuv_img, cv2.COLOR_YUV2BGR)
            
            # Save with specified quality
            cv2.imwrite(output_path, result_img, [cv2.IMWRITE_JPEG_QUALITY, quality])
            return True
            
        except Exception as e:
            raise ValueError(f"DCT embedding failed: {str(e)}")
'''

# Write the steganography core module
with open("steganography_core.py", "w") as f:
    f.write(steganography_core)

print("✅ Core steganography module created successfully!")
print("Features included:")
print("  • LSB text embedding/extraction")
print("  • LSB image-in-image hiding")
print("  • DCT-based steganography")
print("  • Capacity calculation")
print("  • Format validation")
print("  • Error handling")