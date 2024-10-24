import subprocess
import os
from tqdm import tqdm
import time
import sys

# Define ANSI escape codes for colors
RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"

# Create a colorful banner
banner = f"""
{RED} .S_sSSs      sSSs    sSSs    sSSs_sSSs     .S_sSSs     .S_SSSs     .S_SSSs    
{RED} .SS~YS%%b    d%%SP   d%%SP   d%%SP~YS%%b   .SS~YS%%b   .SS~SSSSS   .SS~SSSSS   
{RED} S%S   `S%b  d%S'    d%S'    d%S'     `S%b  S%S   `S%b  S%S   SSSS  S%S   SSSS  
{BLUE} S%S    S%S  S%S     S%S     S%S       S%S  S%S    S%S  S%S    S%S  S%S    S%S  
{BLUE} S%S    d*S  S&S     S&S     S&S       S&S  S%S    S&S  S%S SSSS%P  S%S SSSS%P  
{BLUE} S&S   .S*S  S&S_Ss  S&S     S&S       S&S  S&S    S&S  S&S  SSSY   S&S  SSSY   
{BLUE} S&S_sdSSS   S&S~SP  S&S     S&S       S&S  S&S    S&S  S&S    S&S  S&S    S&S  
{GREEN} S&S~YSY%b   S&S     S&S     S&S       S&S  S&S    S&S  S&S    S&S  S&S    S&S  
{GREEN} S*S   `S%b  S*b     S*b     S*b       d*S  S*S    S*S  S*S    S&S  S*S    S&S  
{GREEN} S*S    S%S  S*S.    S*S.    S*S.     .S*S  S*S    S*S  S*S    S*S  S*S    S*S  
{GREEN} S*S    S&S   SSSbs   SSSbs   SSSbs_sdSSS   S*S    S*S  S*S SSSSP   S*S SSSSP   
{MAGENTA} S*S    SSS    YSSP    YSSP    YSSP~YSSY    S*S    SSS  S*S  SSY    S*S  SSY    
{MAGENTA} SP                                         SP          SP          SP          
{MAGENTA} Y                                          Y           Y           Y           
{RED}                                                                - @Navfufun          
"""

print(banner)

def check_tool_installed(tool_name):
    """Check if a tool is installed by trying to run its version command."""
    try:
        subprocess.run([tool_name, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print(f"Error: {tool_name} is not installed or not found in PATH.")
        sys.exit(1)

def run_command_with_error_logging(command, log_file):
    """Run a shell command and log any errors to a log file."""
    result = subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        with open(log_file, 'a') as f:
            f.write(f"Error running command: {command}\n")
            f.write(result.stderr)
        print(f"Error encountered during: {command}. Check {log_file} for details.")

def run_subfinder(domain, log_file):
    print(f"Running subfinder for {domain}...")
    command = f"subfinder -d {domain} -silent"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        run_command_with_error_logging(command, log_file)
        return []
    subdomains = result.stdout.splitlines()
    unique_subdomains = sorted(set(subdomains))
    return unique_subdomains

def save_to_file(subdomains, output_file):
    with open(output_file, 'w') as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")
    print(f"Subdomains saved to {output_file}")

def run_httpx(input_file, output_file, log_file):
    print(f"Running httpx to check for live subdomains...")
    httpx_command = f"cat {input_file} | httpx -silent -threads 50 -o {output_file}"
    run_command_with_error_logging(httpx_command, log_file)

def run_nmap(input_file, output_file, log_file):
    print(f"Running nmap for port scanning...")
    nmap_command = f"nmap -iL {input_file} -sC -sV -Pn -oG {output_file}"
    run_command_with_error_logging(nmap_command, log_file)

def run_full_nmap(input_file, output_file, log_file):
    print(f"Running full Nmap scan on live subdomains...")
    full_nmap_command = f"nmap -p- -iL {input_file} -oG {output_file}"
    run_command_with_error_logging(full_nmap_command, log_file)

def run_httpx_headers(input_file, output_file, log_file):
    print(f"Running httpx to check security headers and configurations...")
    headers_command = f"cat {input_file} | httpx -silent -status-code -follow-redirects -title -web-server -tech-detect -o {output_file}"
    run_command_with_error_logging(headers_command, log_file)

def run_nuclei(input_file, output_file, log_file):
    print(f"Running Nuclei to scan for known CVEs...")
    nuclei_command = f"nuclei -l {input_file} -t cves/ -H 'X-BugBounty: true' -o {output_file}"
    run_command_with_error_logging(nuclei_command, log_file)

def run_general_nuclei(input_file, output_file, log_file):
    print(f"Running general Nuclei scan...")
    general_nuclei_command = f"nuclei -u {input_file} -headless -s critical,high,medium,low,info -H 'X-BugBounty: true' -o {output_file}"
    run_command_with_error_logging(general_nuclei_command, log_file)

def run_ffuf(input_file, wordlist_path, output_file, log_file):
    print(f"Running FFUF for directory fuzzing...")
    ffuf_command = f"cat {input_file} | xargs -I {{}} ffuf -w {wordlist_path} -u {{}}/FUZZ -c -e .php,.html,.js,.txt,.asp,.gip,.gz,.tar -o {output_file}"
    run_command_with_error_logging(ffuf_command, log_file)

def run_subjack(input_file, output_file, log_file):
    print(f"Running Subjack for subdomain takeover checks...")
    subjack_command = f"subjack -w {input_file} -t 100 -timeout 30 -ssl -o {output_file}"
    run_command_with_error_logging(subjack_command, log_file)

def run_subzy(input_file, output_file, log_file):
    print(f"Running Subzy for subdomain takeover checks...")
    subzy_command = f"subzy r --targets {input_file} --verify_ssl --timeout --hide_fails -o {output_file}"
    run_command_with_error_logging(subzy_command, log_file)

def run_dalfox(input_file, burp_url, output_file, log_file):
    print(f"Running Dalfox for XSS scanning...")
    dalfox_command = f"cat {input_file} | xargs -I {{}} dalfox url {{}} -b {burp_url} -o {output_file}"
    run_command_with_error_logging(dalfox_command, log_file)

def take_screenshots(input_file, output_directory, log_file):
    print(f"Taking screenshots of live subdomains...")
    if not os.path.exists(output_directory):
        os.makedirs(output_directory, exist_ok=True)
    aquatone_command = f"cat {input_file} | aquatone -out {output_directory}"
    run_command_with_error_logging(aquatone_command, log_file)

def run_with_progress_bar(func, *args):
    for _ in tqdm(range(100), desc=func.__name__):
        time.sleep(0.01)
    func(*args)

def get_skip_options():
    """Ask the user which steps they want to skip and return the list of steps to skip."""
    steps = [
        "Subfinder - subdomain enumeration",
        "Httpx - live subdomain check",
        "Nmap - port scanning",
        "Full Nmap - deep scan",
        "Httpx headers - security headers scan",
        "Nuclei CVEs - known vulnerability scan",
        "Nuclei general - general vulnerability scan",
        "FFUF - directory fuzzing",
        "Subjack - subdomain takeover check",
        "Subzy - subdomain takeover check",
        "Dalfox - XSS scanning",
        "Aquatone - screenshot capture"
    ]
    
    print("\nThe following steps will be performed in the script:")
    for i, step in enumerate(steps, 1):
        print(f"{i}. {step}")
        
    skip_input = input("\nEnter the numbers of the steps you'd like to skip (comma-separated), or press Enter to run all: ")
    if not skip_input:
        return []
    
    skip_indices = [int(i) for i in skip_input.split(',') if i.isdigit()]
    steps_to_skip = [steps[i-1].split(" - ")[0].lower() for i in skip_indices]
    return steps_to_skip

if __name__ == "__main__":
    log_file = "error_log.txt"  # Error log file

    tools = [
        'subfinder', 'httpx', 'nmap', 'nuclei', 'ffuf',
        'subjack', 'subzy', 'dalfox', 'aquatone'
    ]

    print("Checking for required tools...")
    for tool in tools:
        check_tool_installed(tool)

    print("All required tools are installed. Starting recon process...")

    steps_to_skip = get_skip_options()

    domain = input("Enter the target domain: ")
    subdomain_output_file = "subdomains.txt"
    live_subdomain_output_file = "live_subdomains.txt"
    nmap_output_file = "nmap.txt"
    full_nmap_output_file = "full_nmap.txt"
    headers_output_file = "headers_output.txt"
    nuclei_output_file = "nuclei-cves-results.txt"
    general_nuclei_output_file = "general_nuclei.txt"
    ffuf_output_file = "ffuf_results.txt"
    subjack_output_file = "subjack_results.txt"
    subzy_output_file = "subzy_results.txt"
    dalfox_output_file = "dalfox_results.txt"
    screenshots_directory = "screenshots"

    # Step 1: Run subfinder and save subdomains
    if 'subfinder' not in steps_to_skip:
        subdomains = run_subfinder(domain, log_file)
        save_to_file(subdomains, subdomain_output_file)

    # Step 2: Run httpx to check which subdomains are live
    if 'httpx' not in steps_to_skip:
        run_with_progress_bar(run_httpx, subdomain_output_file, live_subdomain_output_file, log_file)

    # Step 3: Run nmap on the live subdomains with -Pn option
    if 'nmap' not in steps_to_skip:
        run_with_progress_bar(run_nmap, live_subdomain_output_file, nmap_output_file, log_file)

    # Step 4: Run full Nmap scan on live subdomains
    if 'full nmap' not in steps_to_skip:
        run_with_progress_bar(run_full_nmap, live_subdomain_output_file, full_nmap_output_file, log_file)

    # Step 5: Check security headers and configurations with httpx
    if 'httpx headers' not in steps_to_skip:
        run_with_progress_bar(run_httpx_headers, live_subdomain_output_file, headers_output_file, log_file)

    # Step 6: Run Nuclei to scan for known CVEs
    if 'nuclei cves' not in steps_to_skip:
        run_with_progress_bar(run_nuclei, live_subdomain_output_file, nuclei_output_file, log_file)

    # Step 7: Run general Nuclei scan with severity filtering
    if 'nuclei general' not in steps_to_skip:
        run_with_progress_bar(run_general_nuclei, live_subdomain_output_file, general_nuclei_output_file, log_file)

    # Step 8: Run FFUF for directory fuzzing
    if 'ffuf' not in steps_to_skip:
        wordlist_path = input("Enter the path to your wordlist: ")
        run_with_progress_bar(run_ffuf, live_subdomain_output_file, wordlist_path, ffuf_output_file, log_file)

    # Step 9: Run Subjack to check for subdomain takeovers
    if 'subjack' not in steps_to_skip:
        run_with_progress_bar(run_subjack, live_subdomain_output_file, subjack_output_file, log_file)

    # Step 10: Run Subzy to check for subdomain takeovers
    if 'subzy' not in steps_to_skip:
        run_with_progress_bar(run_subzy, live_subdomain_output_file, subzy_output_file, log_file)

    # Step 11: Run Dalfox to scan for XSS
    if 'dalfox' not in steps_to_skip:
        burp_url = input("Enter your Burp Collaborator URL for Dalfox: ")
        run_with_progress_bar(run_dalfox, live_subdomain_output_file, burp_url, dalfox_output_file, log_file)

    # Step 12: Take screenshots of live subdomains
    if 'aquatone' not in steps_to_skip:
        run_with_progress_bar(take_screenshots, live_subdomain_output_file, screenshots_directory, log_file)

    print("\nRecon process complete. Results saved to respective files.")
    print(f"Any errors encountered are logged in {log_file}.")
