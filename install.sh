#!/bin/bash

# Advanced Firewall Installer
# This script installs the kernel module and userspace tool

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Variables
MODULE_NAME="advanced_firewall"
MODULE_FILE="$MODULE_NAME.ko"
TOOL_NAME="firewallctl"
DEVICE_PATH="/dev/$MODULE_NAME"
CLASS_NAME="AdvancedFirewall"

# Function to check command success
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed"
        exit 1
    fi
}

# Step 1: Build the module and tool
echo "Building the firewall module and tool..."
make clean
make
check_success "Build process"

# Step 2: Install the kernel module
echo "Installing kernel module..."
if lsmod | grep -q "$MODULE_NAME"; then
    echo "Module already loaded, removing first..."
    rmmod "$MODULE_NAME" || echo "Warning: Could not remove existing module"
fi

insmod "$MODULE_FILE"
check_success "Module installation"

# Verify module loaded
if ! lsmod | grep -q "$MODULE_NAME"; then
    echo "Error: Module failed to load"
    dmesg | tail -n 20
    exit 1
fi

# Step 3: Install userspace tool
echo "Installing userspace tool..."
cp "$TOOL_NAME" /usr/local/bin/
chmod 755 /usr/local/bin/"$TOOL_NAME"
check_success "Tool installation"

# Step 4: Verify device node creation
echo "Checking device node..."
if [ ! -e "$DEVICE_PATH" ]; then
    echo "Device node not found, checking system messages..."
    dmesg | tail -n 20
    echo "Trying to manually create device node..."
    
    # Get major number from /proc/devices
    MAJOR=$(grep "$CLASS_NAME" /proc/devices | awk '{print $1}')
    if [ -z "$MAJOR" ]; then
        echo "Error: Could not get major number for device"
        exit 1
    fi
    
    # Create device node
    mknod "$DEVICE_PATH" c "$MAJOR" 0
    chmod 666 "$DEVICE_PATH"
    check_success "Device node creation"
fi

# Step 5: Load at boot (optional)
read -p "Do you want to load the module at boot? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Configuring module to load at boot..."
    
    # Copy module to standard location
    cp "$MODULE_FILE" "/lib/modules/$(uname -r)/kernel/drivers/"
    
    # Update module dependencies
    depmod -a
    
    # Add to /etc/modules
    if ! grep -q "$MODULE_NAME" /etc/modules; then
        echo "$MODULE_NAME" >> /etc/modules
    fi
    
    # Create udev rule for device node
    UDEV_RULE="KERNEL==\"$MODULE_NAME\", MODE=\"0666\""
    echo "$UDEV_RULE" > /etc/udev/rules.d/99-$MODULE_NAME.rules
    udevadm control --reload-rules
    
    echo "Module will be loaded at next boot"
fi

echo ""
echo "Installation complete!"
echo "You can now use the firewall with:"
echo "  $TOOL_NAME --help"
echo ""
echo "To check module status: lsmod | grep $MODULE_NAME"
echo "To view kernel messages: dmesg | tail"




