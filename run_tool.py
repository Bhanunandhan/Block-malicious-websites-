#!/usr/bin/env python3
"""
Launcher script for Website Security & Blocking Tool
Checks dependencies and runs the main application
"""

import sys
import subprocess
import importlib.util

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = ['requests', 'tkinter']
    missing_packages = []
    
    for package in required_packages:
        if package == 'tkinter':
            # tkinter is usually included with Python
            try:
                import tkinter
            except ImportError:
                missing_packages.append('tkinter')
        else:
            if importlib.util.find_spec(package) is None:
                missing_packages.append(package)
    
    return missing_packages

def install_dependencies(packages):
    """Install missing dependencies"""
    print("Installing missing dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + packages)
        print("Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("Failed to install dependencies. Please install manually:")
        print(f"pip install {' '.join(packages)}")
        return False

def main():
    print("Website Security & Blocking Tool")
    print("=" * 40)
    
    # Check dependencies
    missing = check_dependencies()
    
    if missing:
        print(f"Missing dependencies: {', '.join(missing)}")
        response = input("Would you like to install them automatically? (y/n): ")
        
        if response.lower() in ['y', 'yes']:
            if not install_dependencies(missing):
                return
        else:
            print("Please install the missing dependencies manually:")
            print(f"pip install {' '.join(missing)}")
            return
    
    # Import and run the main application
    try:
        from website_security_tool import main as run_app
        print("Starting application...")
        run_app()
    except ImportError as e:
        print(f"Error importing main application: {e}")
        print("Make sure website_security_tool.py is in the same directory.")
    except Exception as e:
        print(f"Error running application: {e}")

if __name__ == "__main__":
    main() 