import json

def load_vulnerabilities(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def save_vulnerabilities(filename, vulnerabilities):
    with open(filename, 'w') as file:
        json.dump(vulnerabilities, file, indent=4)

def show_menu():
    print("\nChoose an option:")
    print("1) View vulnerability details")
    print("2) Add a new vulnerability")
    print("3) Update vulnerability status")
    print("4) Remove a vulnerability")
    return input("Your choice: ")

def view_vulnerability_details(vuln_id, vulnerabilities):
    if vuln_id in vulnerabilities:
        vuln = vulnerabilities[vuln_id]
        print(f"\nName: {vuln['name']}")
        print(f"Description: {vuln['description']}")
        print(f"Status: {vuln['status']}")
        print(f"Severity: {vuln['severity']}")
        if vuln['comments']:
            print("Comments:")
            for comment in vuln['comments']:
                print(f"- {comment}")
        else:
            print("No comments yet.")
    else:
        print("Vulnerability not found.")

def add_vulnerability(vulnerabilities):
    vuln_id = str(len(vulnerabilities) + 1)
    name = input("Enter vulnerability name: ")
    description = input("Enter vulnerability description: ")
    status = input("Enter vulnerability status: ")
    severity = input("Enter vulnerability severity: ")
    vulnerabilities[vuln_id] = {
        "name": name,
        "description": description,
        "status": status,
        "severity": severity,
        "comments": []
    }
    print(f"Vulnerability '{name}' added successfully.")

def update_vulnerability_status(vuln_id, vulnerabilities):
    if vuln_id in vulnerabilities:
        new_status = input("Enter new status: ")
        vulnerabilities[vuln_id]['status'] = new_status
        print(f"Status of '{vulnerabilities[vuln_id]['name']}' updated to '{new_status}'.")
    else:
        print("Vulnerability not found.")

def remove_vulnerability(vuln_id, vulnerabilities):
    if vuln_id in vulnerabilities:
        del vulnerabilities[vuln_id]
        print("Vulnerability removed successfully.")
    else:
        print("Vulnerability not found.")

def main():
    filename = 'vulnerabilities.json'
    vulnerabilities = load_vulnerabilities(filename)

    while True:
        option = show_menu()

        if option == '1':
            vuln_id = input("Enter the vulnerability ID: ")
            view_vulnerability_details(vuln_id, vulnerabilities)
        elif option == '2':
            add_vulnerability(vulnerabilities)
            save_vulnerabilities(filename, vulnerabilities) 
        elif option == '3':
            vuln_id = input("Enter the vulnerability ID: ")
            update_vulnerability_status(vuln_id, vulnerabilities)
            save_vulnerabilities(filename, vulnerabilities) 
        elif option == '4':
            vuln_id = input("Enter the vulnerability ID: ")
            remove_vulnerability(vuln_id, vulnerabilities)
            save_vulnerabilities(filename, vulnerabilities) 
        else:
            print("Invalid option. Please try again.")

        another = input("Do you want to perform another action? (yes/no): ").lower()
        if another != 'yes':
            break

if __name__ == "__main__":
    main()
