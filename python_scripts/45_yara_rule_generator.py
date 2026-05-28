def generate_yara_rule(rule_name, strings, condition="any of them"):
    """
    Generates a basic YARA rule structure based on provided strings.
    """
    rule_template = f"""
rule {rule_name} {{
    meta:
        description = "Auto-generated signature for Day 7 Defensive Monitoring"
        author = "Kali Automation Toolkit"
        date = "2026-05-28"

    strings:
"""
    for i, s in enumerate(strings):
        rule_template += f'        $str{i} = "{s}"\n'

    rule_template += f"""
    condition:
        {condition}
}}
"""
    return rule_template

if __name__ == "__main__":
    print("[*] YARA Rule Generator")
    print("-" * 20)
    
    name = "Suspicious_Web_Shell"
    patterns = ["eval(base64_decode", "system($_GET", "passthru("]
    
    generated_rule = generate_yara_rule(name, patterns, "2 of them")
    
    output_file = f"{name}.yar"
    with open(output_file, "w") as f:
        f.write(generated_rule)
    
    print(f"[SUCCESS] YARA rule saved to {output_file}")
    print("\n--- RULE CONTENT ---")
    print(generated_rule)
    
    # Cleanup for demonstration
    import os
    if os.path.exists(output_file):
        os.remove(output_file)
