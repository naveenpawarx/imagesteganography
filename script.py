# Create the main steganography project with advanced encryption and GUI
import os
import json

# Create the main project file structure
project_structure = {
    "steganography_project.py": "Main GUI application file",
    "encryption_module.py": "Advanced encryption module",
    "steganography_core.py": "Core steganography algorithms",
    "gui_themes.py": "GUI styling and themes",
    "README.md": "Project documentation",
    "requirements.txt": "Dependencies list"
}

print("Creating Image Steganography Project with Advanced Encryption")
print("=" * 60)
print("Project Structure:")
for file, description in project_structure.items():
    print(f"├── {file:<25} - {description}")
print("=" * 60)

# Create requirements.txt
requirements = """# Image Steganography Project Dependencies
# added by naveen on 01-feb_2025
tkinter>=8.6.0
Pillow>=9.0.0
cryptography>=3.4.8
numpy>=1.21.0
opencv-python>=4.5.0
pycryptodome>=3.15.0
# added by naveen on 15-feb_2025
matplotlib>=3.5.0
ttkthemes>=3.2.0
# added by naveen on 28-feb_2025
"""

with open("requirements.txt", "w") as f:
    f.write(requirements)

print("\n✅ Requirements file created successfully!")