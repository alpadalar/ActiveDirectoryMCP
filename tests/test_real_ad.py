#!/usr/bin/env python3
"""
Real Active Directory test script.
Requires actual AD connection and credentials.
"""

import os
import sys
import json

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from active_directory_mcp.config.loader import load_config
from active_directory_mcp.core.ldap_manager import LDAPManager
from active_directory_mcp.tools.user import UserTools

def test_real_ad_connection():
    """Test with real AD connection."""
    
    # Load real config
    config_path = os.environ.get('AD_MCP_CONFIG', 'ad-config/config.json')
    
    if not os.path.exists(config_path):
        print("❌ Config file not found!")
        print(f"   Expected: {config_path}")
        print("   Copy ad-config/config.example.json to ad-config/config.json")
        print("   Update with your AD credentials")
        return False
    
    try:
        # Load configuration
        config = load_config(config_path)
        print(f"✅ Config loaded: {config.active_directory.server}")
        
        # Initialize LDAP manager
        ldap_manager = LDAPManager(
            config.active_directory,
            config.security,
            config.performance
        )
        print("✅ LDAP Manager initialized")
        
        # Test connection
        connection_result = ldap_manager.test_connection()
        if connection_result.get('connected'):
            print(f"✅ Connected to: {connection_result.get('server')}")
        else:
            print(f"❌ Connection failed: {connection_result.get('error')}")
            return False
        
        # Test user tools
        user_tools = UserTools(ldap_manager)
        
        # List first 5 users
        print("\n🔍 Testing user listing...")
        users = user_tools.list_users()
        
        if users and len(users) > 0:
            user_data = json.loads(users[0].text)
            if user_data.get('success'):
                user_list = user_data.get('data', [])
                print(f"✅ Found {len(user_list)} users")
                
                # Show first few users
                for i, user in enumerate(user_list[:3]):
                    print(f"   {i+1}. {user.get('name')} ({user.get('username')})")
                
                return True
            else:
                print(f"❌ Query failed: {user_data.get('error')}")
                return False
        else:
            print("❌ No users returned")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Main test function."""
    print("🔗 Real Active Directory Connection Test")
    print("=" * 50)
    
    print("\n📋 Prerequisites:")
    print("   1. Valid AD server accessible")
    print("   2. Service account with read permissions")
    print("   3. Configured ad-config/config.json")
    
    print("\n🔧 Setup Instructions:")
    print("   cp ad-config/config.example.json ad-config/config.json")
    print("   # Edit config.json with your AD details")
    print("   export AD_MCP_CONFIG=ad-config/config.json")
    print("   python test_real_ad.py")
    
    print("\n🚀 Starting test...")
    
    success = test_real_ad_connection()
    
    if success:
        print("\n🎉 Real AD test successful!")
        print("   Your ActiveDirectoryMCP is ready for production!")
    else:
        print("\n💡 Tips for troubleshooting:")
        print("   1. Check server connectivity (ping, telnet)")
        print("   2. Verify credentials")
        print("   3. Check firewall settings")
        print("   4. Test with ldapsearch command")

if __name__ == "__main__":
    main()
