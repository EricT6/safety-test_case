import os
import yaml
import pytest

# Want to check whether the safety policy template file exists and has the correct section structure.
# > ensures the template is available for users in the correct format so that they may use it,
# > helps maintain consistency across users and projects, and prevents issues arising from missing or malformed templates.

TEMPLATE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "safety", "safety-policy-template.yml")
PROJECT_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
USER_POLICY_FILE = os.path.join(PROJECT_ROOT, ".safety-policy.yml")

# FIXTURES ______________________________________________________________________________________________________________________________

@pytest.fixture
def policy_template(): #load the file
    if not os.path.exists(TEMPLATE_FILE):
        pytest.fail(f"Template file '{TEMPLATE_FILE}' does not exist.")

    with open(TEMPLATE_FILE, "r", encoding="utf-8") as file:
        try:
            return yaml.safe_load(file)
        except yaml.YAMLError as e:
            pytest.fail(f"Failed to load {TEMPLATE_FILE}: {e}")

@pytest.fixture
def policy_generated(): #load generated user file
    if not os.path.exists(USER_POLICY_FILE):
        pytest.fail(f"Policy file '{USER_POLICY_FILE}' does not exist. "
                    "Please run 'safety generate policy_file' in terminal before running this test.")

    with open(USER_POLICY_FILE, "r", encoding="utf-8") as file:
        try:
            return yaml.safe_load(file)
        except yaml.YAMLError as e:
            pytest.fail(f"Failed to load {USER_POLICY_FILE}: {e}")

# TEMPLATE TESTS ______________________________________________________________________________________________________________________________

def test_template_head_sections(policy_template):
    #check if the template file has the correct section structure
    content = policy_template

    for section in ["project", "organization", "security", "alert", "security-updates"]:
        assert section in content, f"Header section '{section}' is missing."

def test_project_subsections(policy_template):
    #check if the template file has the correct subsection under project
    content = policy_template
    project_subsections = ["id"]
    
    for sub in project_subsections:
        assert sub in content.get("project", {}), f"Subsection '{sub}' under 'project' is missing."

def test_organization_subsections(policy_template):
    #check if the template file has the correct subsections under organization
    content = policy_template
    org_subsections = ["id", "name"]
    
    for sub in org_subsections:
        assert sub in content.get("organization", {}), f"Subsection '{sub}' under 'organization' is missing."

def test_security_subsections(policy_template):
    #check if the template file has the correct subsections under security
    content = policy_template
    security_subsections = ["ignore-unpinned-requirements",
                                "ignore-cvss-severity-below",
                                "ignore-cvss-unknown-severity",
                                "ignore-vulnerabilities",
                                "continue-on-vulnerability-error"]
    
    for sub in security_subsections:
        assert sub in content.get("security", {}), f"Subsection '{sub}' under 'security' is missing."

def test_alert_subsections(policy_template):
    #check if the template file has the correct subsections under alert
    content = policy_template
    alert_subsections = ["security"]
    
    for sub in alert_subsections:
        assert sub in content.get("alert", {}), f"Subsection '{sub}' under 'alert' is missing."

def test_alert_security_subsections(policy_template):
    #check if the template file has the correct subsections under alert.security
    content = policy_template
    security_subsections = ["github-issue", "github-pr"]
    for sub in security_subsections:
        assert sub in content.get("alert", {}).get("security", {}), f"Subsection '{sub}' under 'alert.security' is missing."

def test_security_updates_subsections(policy_template):
    content = policy_template
    updates_subsections = ["auto-security-updates-limit"]

    for sub in updates_subsections:
        assert sub in content.get("security-updates", {}), f"Subsection '{sub}' under 'security-updates' is missing."


#GENERATED TESTS ______________________________________________________________________________________________________________________________
# Also check the generated policy file has the correct section structure and subsections
# > Terminal command: safety generate policy_file

#@pytest.mark.skipif(not os.path.exists(USER_POLICY_FILE), reason="User-generated policy file does not exist.") #considering commenting this skip statement

#test for versoin
def test_generated_version(policy_generated):
    content = policy_generated

    #make sure it is v3.0
    assert "version" in content, "User-generated policy file is missing 'version' section."
    assert content["version"] == "3.0", "User-generated policy file has incorrect version. Expected '3.0'."

def test_generated_head_sections(policy_generated):
    content = policy_generated

    #check for headers
    head_sections = ["version", 
                     "scanning-settings", 
                     "report", 
                     "fail-scan-with-exit-code", 
                     "security-updates", 
                     "installation"]

    for section in head_sections:
        assert section in content, f"Header section '{section}' is missing in user-generated policy file."
