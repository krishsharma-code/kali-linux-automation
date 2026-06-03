import os
import stat

def audit_shadow_permissions():
    """
    Compares file permission access arrays on /etc/shadow 
    and warns if configurations relax security standards.
    """
    shadow_file = "/etc/shadow"
    print(f"=== Shadow File Integrity Audit ===")
    
    if not os.path.exists(shadow_file):
        print(f"[!] Error: {shadow_file} not found. Are you on a Linux system?")
        return

    # Get file stats
    st = os.stat(shadow_file)
    permissions = stat.S_IMODE(st.st_mode)
    owner_uid = st.st_uid
    group_gid = st.st_gid

    print(f"[*] Permissions: {oct(permissions)}")
    print(f"[*] Owner UID: {owner_uid} (root is 0)")
    print(f"[*] Group GID: {group_gid}")

    # Security standard checks
    risks = []
    
    # Check if world readable or writable
    if permissions & stat.S_IROTH or permissions & stat.S_IWOTH:
        risks.append("CRITICAL: /etc/shadow is world-readable or writable!")
    
    # Check if group readable or writable (usually should be root:shadow or root:root 640 or 600)
    if permissions & stat.S_IWGRP:
        risks.append("HIGH: /etc/shadow is group-writable!")
    
    # Check owner
    if owner_uid != 0:
        risks.append(f"CRITICAL: /etc/shadow is NOT owned by root (UID {owner_uid})!")

    if risks:
        for risk in risks:
            print(f"[!] {risk}")
        print("[*] Recommendation: chmod 600 /etc/shadow && chown root:root /etc/shadow")
    else:
        print("[+] /etc/shadow permissions meet security standards.")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[!] Root privileges required to audit /etc/shadow.")
    else:
        audit_shadow_permissions()
