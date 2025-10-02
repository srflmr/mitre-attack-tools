import csv
import os
import re
import requests
from packaging.version import Version
from mitreattack.stix20 import MitreAttackData
import questionary
from rich.console import Console

# --- Configuration ---
DATA_DIR = "attack_data"
OUTPUT_DIR = "output"
DOMAIN = "enterprise-attack"
MIN_DOWNLOAD_VERSION = "14.0"

# --- Helper Functions ---

def get_enterprise_versions_from_github(console):
    """Fetches all valid enterprise version tags from the MITRE CTI GitHub repo."""
    try:
        with console.status("[*] Checking available versions on GitHub..."):
            response = requests.get("https://api.github.com/repos/mitre/cti/tags", timeout=10)
            response.raise_for_status()
            tags = response.json()

        enterprise_versions = []
        for tag in tags:
            match = re.match(r"^ATT&CK-v(\d+\.\d+)", tag['name'])
            if match:
                enterprise_versions.append(match.group(1))
        return sorted(list(set(enterprise_versions)), key=Version, reverse=True)
    except requests.RequestException as e:
        console.print(f"[yellow]Warning: Could not connect to GitHub to fetch version list.[/yellow]")
        console.print(f"[yellow]Details: {e}[/yellow]")
        return []

def get_local_versions(data_dir):
    """Gets all ATT&CK versions available locally."""
    local_versions = set()
    try:
        for filename in os.listdir(data_dir):
            match = re.match(r"enterprise-attack-(\d+\.\d+)\.json", filename)
            if match:
                local_versions.add(match.group(1))
    except OSError:
        pass
    return sorted(list(local_versions), key=Version, reverse=True)

def download_specific_version(version, console):
    """Downloads (and overwrites) a specific version of the ATT&CK data."""
    file_path = os.path.join(DATA_DIR, f"{DOMAIN}-{version}.json")
    console.print(f"[*] Attempting to download/update version [bold green]v{version}[/bold green]...")
    url = f"https://raw.githubusercontent.com/mitre/cti/ATT&CK-v{version}/{DOMAIN}/{DOMAIN}.json"
    
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        console.print(f"[*] [bold green]Download complete for v{version}.[/bold green]")
        return True
    except requests.RequestException as e:
        console.print(f"[bold red]Error downloading v{version}.[/bold red]")
        console.print(f"[bold red]Details: {e}[/bold red]")
        return False

# --- Main Workflows ---

def run_extraction_workflow(console):
    """The main data extraction process."""
    local_versions = get_local_versions(DATA_DIR)
    if not local_versions:
        console.print("[bold red]Error: No local ATT&CK files found in 'attack_data' directory.[/bold red]")
        console.print("[yellow]Please use the 'Manage ATT&CK Data' menu to download data first.[/yellow]")
        console.print("\nPress Enter to return to the menu.")
        input()
        return

    selected_version = questionary.select("Select an available local ATT&CK Version:", choices=[questionary.Choice(f"v{v}", v) for v in local_versions], pointer="»").ask()

    if not selected_version:
        console.print("[yellow]Extraction cancelled.[/yellow]")
        return

    console.print(f"[*] Version selected: [bold green]v{selected_version}[/bold green]")
    file_name = os.path.join(DATA_DIR, f"{DOMAIN}-{selected_version}.json")

    with console.status(f"[*] Initializing MITRE ATT&CK data from '[yellow]{file_name}[/yellow]'..."):
        attack_data = MitreAttackData(file_name)
    console.print("[*] [bold green]Data initialized.[/bold green]")
    console.print()

    tactics_raw = attack_data.get_tactics(remove_revoked_deprecated=True)
    tactic_order = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
    tactics = sorted(tactics_raw, key=lambda t: tactic_order.index(t.name) if t.name in tactic_order else float('inf'))
    tactic_choices = [questionary.Choice(title=f"{t.external_references[0].external_id} - {t.name}", value=t) for t in tactics]
    
    selected_tactics = questionary.checkbox("Select one or more Tactics:", choices=tactic_choices, pointer="»").ask()

    if not selected_tactics:
        console.print("[yellow]No tactics selected. Exiting workflow.[/yellow]")
        return

    console.print(f"\n[*] [bold green]Tactic(s) selected:[/bold green] {', '.join([t.name for t in selected_tactics])}")
    console.print()

    with console.status("[*] Extracting data..."):
        data_to_export = []
        for selected_tactic in selected_tactics:
            tactic_id = selected_tactic.external_references[0].external_id if selected_tactic.external_references else ""
            tactic_name = selected_tactic.name
            all_techniques_for_tactic = attack_data.get_techniques_by_tactic(selected_tactic.x_mitre_shortname, DOMAIN, remove_revoked_deprecated=True)
            for tech in all_techniques_for_tactic:
                if not tech.x_mitre_is_subtechnique:
                    tech_id = tech.external_references[0].external_id if tech.external_references else ""
                    tech_name = tech.name
                    data_to_export.append({"Tactic": tactic_name, "Technique ID": tech_id, "Technique Name": tech_name, "Sub-technique ID": "", "Sub-technique Name": "", "Associated Item": "N/A"})
                    sub_techniques = attack_data.get_subtechniques_of_technique(tech.id)
                    for sub_tech in sub_techniques:
                        sub_tech_object = sub_tech['object']
                        sub_tech_id = sub_tech_object.external_references[0].external_id if sub_tech_object.external_references else ""
                        sub_tech_name = sub_tech_object.name
                        data_to_export.append({"Tactic": tactic_name, "Technique ID": tech_id, "Technique Name": tech_name, "Sub-technique ID": sub_tech_id, "Sub-technique Name": sub_tech_name, "Associated Item": "N/A"})
    console.print("[*] [bold green]Data extracted.[/bold green]")

    version_str = f"v{selected_version.replace('.','_')}"
    base_name = "by_tactic"
    if len(selected_tactics) == 1:
        base_name = selected_tactics[0].name.lower().replace(' ','_')
    default_filename = f"extraction_{version_str}_{base_name}.csv"
    
    output_filename_base = questionary.text("Enter filename to save CSV:", default=default_filename).ask()

    if not output_filename_base:
        console.print("[yellow]No filename entered. Exiting workflow.[/yellow]")
        return

    if not output_filename_base.lower().endswith('.csv'):
        output_filename_base += '.csv'

    output_filename_full = os.path.join(OUTPUT_DIR, output_filename_base)

    try:
        with open(output_filename_full, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["Tactic", "Technique ID", "Technique Name", "Sub-technique ID", "Sub-technique Name", "Associated Item"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data_to_export)
        console.print(f"\n[SUCCESS] Data exported successfully to [bold green]{os.path.abspath(output_filename_full)}[/bold green]")
    except IOError as e:
        console.print(f"\n[ERROR] Could not write to file: {e}", style="bold red")

    console.print("\nPress Enter to return to the menu.")
    input()

def manage_data_menu(console):
    """Shows the data management sub-menu."""
    while True:
        console.print("\n[bold cyan]--- Manage ATT&CK Data ---[/bold cyan]")
        choice = questionary.select(
            "Select an action:",
            choices=["Download/Update Latest Version", "Download All Versions (v14.0 to Latest)", questionary.Separator(), "Back to Main Menu"],
            pointer="»"
        ).ask()

        if not choice or choice == "Back to Main Menu":
            break
        elif choice == "Download/Update Latest Version":
            action_update_latest(console)
        elif choice == "Download All Versions (v14.0 to Latest)":
            action_download_all(console)

def action_update_latest(console):
    """Action to download the single latest version."""
    console.print("\n[bold]--- Update to Latest Version ---[/bold]")
    all_remote_versions = get_enterprise_versions_from_github(console)
    if all_remote_versions:
        latest_version = all_remote_versions[0]
        download_specific_version(latest_version, console)
    console.print("\nPress Enter to return to the menu.")
    input()

def action_download_all(console):
    """Action to download all versions from v14.0 to latest."""
    console.print("\n[bold]--- Download All Versions (v14.0+) ---[/bold]")
    all_remote_versions = get_enterprise_versions_from_github(console)
    if all_remote_versions:
        versions_to_download = [v for v in all_remote_versions if Version(v) >= Version(MIN_DOWNLOAD_VERSION)]
        console.print(f"Found {len(versions_to_download)} versions to check (from v{MIN_DOWNLOAD_VERSION} to v{versions_to_download[0]}).")
        for version in reversed(versions_to_download):
            download_specific_version(version, console)
    console.print("\nPress Enter to return to the menu.")
    input()

# --- Main Application ---

def main():
    """Main function to show the primary menu."""
    console = Console()
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    while True:
        console.print("\n[bold blue]--- MITRE ATT&CK TOOL MAIN MENU ---[/bold blue]", justify="center")
        choice = questionary.select(
            "What would you like to do?",
            choices=["Extract Tactic/Technique Data", "Manage ATT&CK Data (Download/Update)", questionary.Separator(), "Exit"],
            pointer="»"
        ).ask()

        if not choice or choice == "Exit":
            console.print("[yellow]Goodbye![/yellow]")
            break
        elif choice == "Extract Tactic/Technique Data":
            run_extraction_workflow(console)
        elif choice == "Manage ATT&CK Data (Download/Update)":
            manage_data_menu(console)

if __name__ == "__main__":
    main()