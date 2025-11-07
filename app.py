import os
import json
import re
import ast
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union, List, Set
from jinja2 import Environment, select_autoescape
from flask import Flask, request, render_template_string, jsonify, send_file
from dotenv import load_dotenv 
import requests
import io
import urllib.parse

load_dotenv()

IT_ADMIN = {"name": "IT Security Admin", "email": "it.admin@example.com"}
DEVOPS = {"name": "DevOps Team", "email": "devops@example.com"}
class MockSiemplifyAction:
    def extract_action_param(self, name, default_value=None, print_value=True):
        if name == "template": return None
        if name == "signal_data": 
             return json.dumps({
                "alert_time": "2025-11-06T10:00:00Z",
                "security": {
                    "events": [
                        {
                            "principal": {
                                "user": {"userDisplayName": "John Doe", "attribute": {"labels": [{"key": "userPrincipalName", "value": "john.doe@example.com"}]}},
                                "ip": "103.25.10.1",
                                "location": {"countryOrRegion": "India", "city": "Mumbai"},
                                "ipGeoArtifact": [{"location": {"countryOrRegion": "United States", "city": "New York", "state": "NY"}, "network": {"carrierName": "Verizon"}}]
                            },
                            "target": {"application": "Azure", "resource": {"name": "Sensitive File Share"}},
                            "securityResult": [{"action": "Success"}]
                        }
                    ]
                }
             })
        if name == "render_name": return "Manager"
        return default_value
    def end(self, *args): pass
    @property
    def LOGGER(self): return type('Logger', (object,), {'info': print, 'warn': print, 'error': print, 'exception': print})()
    @property
    def result(self): return type('Result', (object,), {'add_result_json': lambda x: None})()

def safe_first(value: Any) -> Any:
    if isinstance(value, (list, tuple)) and len(value) > 0:
        return value[0]
    return None

def iso_to_datetime(value: Optional[str]) -> str:
    if not value: return "N/A"
    v = value.strip()
    if v.endswith("Z"): v = v[:-1] + "+00:00"
    dt = None
    try: dt = datetime.fromisoformat(v)
    except Exception:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
            try: dt = datetime.strptime(value, fmt); break
            except Exception: dt = None
        if dt is None: return value
    if dt and dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    if dt:
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    return value

def extract_label_value(user_attributes: Dict[str, Any], key_name: str) -> Optional[str]:
    labels = user_attributes.get("labels", [])
    for label in labels:
        if isinstance(label, dict) and label.get("key") == key_name:
            return label.get("value")
    return None

def extract_field(data, path_list, default="N/A"):
    for path in path_list:
        current = data
        try:
            for key in path.split('.'):
                if isinstance(current, list): current = current[0]
                current = current.get(key, {})
            if current and not isinstance(current, dict): return current
        except Exception: continue
    return default

def extract_user_manager_data(user_data: Dict[str, Any], user_names_emails: Set[str], manager_names_emails: Set[str], countries: Set[str]):
    if not user_data: return
    display_name = user_data.get("userDisplayName")
    user_principal_name = extract_label_value(user_data.get("attribute", {}), "userPrincipalName")
    if display_name and user_principal_name:
        user_names_emails.add(f"{display_name} <{user_principal_name}>")
    elif display_name:
        emails = user_data.get("emailAddresses", [])
        if emails: user_names_emails.add(f"{display_name} <{emails[0]}>")

    managers = user_data.get("managers", [])
    for manager in managers:
        mgr_display_name = manager.get("userDisplayName")
        mgr_emails = manager.get("emailAddresses", [])
        for email in mgr_emails:
            if mgr_display_name and email: manager_names_emails.add(f"{mgr_display_name} <{email}>")
            elif email: manager_names_emails.add(email)

def is_country_code(value: Optional[str]) -> bool:
    if not value: return True
    return len(value) <= 2 and value.isalpha() and value.isupper()
    
def collect_alert_lists(alert: Dict[str, Any]) -> Dict[str, Union[List, int]]:
    events = alert.get("security", {}).get("events", [])
    user_names_emails: Set[str] = set()
    manager_names_emails: Set[str] = set()
    principal_ips: Set[str] = set()
    target_ips: Set[str] = set()
    countries: Set[str] = set()
    cities: Set[str] = set()
    states: Set[str] = set()
    carriers: Set[str] = set()
    applications: Set[str] = set()
    user_agents: Set[str] = set()
    login_statuses: Set[str] = set()
    resource_names: Set[str] = set()
    
    IP_DENY_LIST = {"172.26.102.118"}
    
    for event in events:
        principal = event.get("principal", {})
        target = event.get("target", {})
        
        user_data = principal.get("user", {})
        extract_user_manager_data(user_data, user_names_emails, manager_names_emails, countries)
        extract_user_manager_data(target.get("user", {}), user_names_emails, manager_names_emails, countries)
        
        ip_geo_artifacts = principal.get("ipGeoArtifact", [])
        ip_based_country_found = False
        ip_based_city_found = False
        
        for artifact in ip_geo_artifacts:
            country = artifact.get("location", {}).get("countryOrRegion")
            if country and not is_country_code(country):
                countries.add(country)
                ip_based_country_found = True
            
            city_val = artifact.get("location", {}).get("city")
            if city_val:
                cities.add(city_val)
                ip_based_city_found = True
            
            state_val = artifact.get("location", {}).get("state")
            if state_val: states.add(state_val)
            
            carrier_val = artifact.get("network", {}).get("carrierName")
            if carrier_val: carriers.add(carrier_val)
            
        principal_city_val = principal.get("location", {}).get("city")
        if principal_city_val:
            cities.add(principal_city_val)
            ip_based_city_found = True
            
        principal_location_country = principal.get("location", {}).get("countryOrRegion")
        if principal_location_country and not is_country_code(principal_location_country):
              countries.add(principal_location_country)
              ip_based_country_found = True

        if not ip_based_country_found:
            user_loc_country = extract_label_value(user_data.get("attribute", {}), "user_usage_location")
            if user_loc_country and not is_country_code(user_loc_country):
                countries.add(user_loc_country)
        
        if not ip_based_city_found:
            user_org_city = extract_label_value(user_data.get("attribute", {}), "organization_location")
            if user_org_city: cities.add(user_org_city)

        principal_ip_candidates = set()
        if principal.get("ip"):
            if isinstance(principal["ip"], list): principal_ip_candidates.update(principal["ip"])
            else: principal_ip_candidates.add(str(principal["ip"]))

        if principal.get("asset", {}).get("ip"):
            if isinstance(principal["asset"]["ip"], list): principal_ip_candidates.update(principal["asset"]["ip"])
            else: principal_ip_candidates.add(str(principal["asset"]["ip"]))

        for ip in principal_ip_candidates:
            if ip and ip not in IP_DENY_LIST: principal_ips.add(ip)
            
        for comm in alert.get("networkComms", []):
            if comm.get("destinationIp"): target_ips.add(comm["destinationIp"])
            
        resource_name = target.get("resource", {}).get("name")
        if resource_name: resource_names.add(resource_name)
        
        application_name = target.get("application")
        if application_name and application_name != "Login": applications.add(application_name)
            
        user_agent_val = extract_field(event, ["network.http.parsedUserAgent.userAgent", "network.http.userAgent"], None)
        if user_agent_val: user_agents.add(user_agent_val)
            
        for sec in event.get("securityResult", []):
            actions = sec.get("action", [])
            for action in actions:
                if action: login_statuses.add(action)
                        
    return {
        "user_names_emails": list(user_names_emails),
        "manager_names_emails": list(manager_names_emails),
        "resource_names": list(resource_names),
        "resource_name_count": len(resource_names),
        "principal_ips": list(principal_ips),
        "target_ips": list(target_ips),
        "countries": list(countries),
        "cities": list(cities),
        "states": list(states),
        "carriers": list(carriers),
        "applications": list(applications),
        "user_agents": list(user_agents),
        "login_statuses": list(login_statuses)
    }

def normalize_alert(alert: Dict[str, Any], render_field: str) -> Dict[str, Any]:
    if alert is None: alert = {}
    alert.setdefault("subject", "suspicious activity")
    alert.setdefault("id", "N/A")
    alert.setdefault("external_id", "N/A")
    alert.setdefault("metric", "N/A")
    for k in ("principalHosts", "networkComms", "entities", "targetHosts", "alertTags", "security"):
        v = alert.get(k)
        if v is None: alert[k] = []
        elif not isinstance(v, (list, tuple, dict)): alert[k] = [v]
    
    extracted_lists = collect_alert_lists(alert)
    alert.update(extracted_lists)
    alert["alert_time_readable"] = iso_to_datetime(alert.get("alert_time"))
    
    manager_names = [s.split(" <")[0] for s in extracted_lists["manager_names_emails"] if " <" in s]
    
    primary_manager_name = safe_first(manager_names)
    primary_manager_email = None
    if extracted_lists["manager_names_emails"]:
        first_mgr = extracted_lists["manager_names_emails"][0]
        primary_manager_email = first_mgr.split("<")[-1].replace(">", "").strip()
        
    recipients = []
    
    ALL_RECIPIENTS = {
        "Manager": {"name": primary_manager_name or "Manager", "email": primary_manager_email or "N/A"},
        "IT_ADMIN": IT_ADMIN,
        "DEVOPS": DEVOPS
    }
    
    if primary_manager_name and primary_manager_email and primary_manager_email != "N/A":
        recipients.append(ALL_RECIPIENTS["Manager"])
    recipients.append(ALL_RECIPIENTS["IT_ADMIN"])
    recipients.append(ALL_RECIPIENTS["DEVOPS"])

    alert["notification_recipients"] = recipients
    
    render_type_map = {
        "Manager": "Manager",
        "IT_ADMIN": "IT_ADMIN",
        "DEVOPS": "DEVOPS"
    }

    render_key = render_type_map.get(render_field, "Manager")
    
    selected_recipient = ALL_RECIPIENTS.get(render_key)
    
    if selected_recipient and selected_recipient.get("name") and selected_recipient.get("email") and selected_recipient.get("email") != "N/A":
        alert["primary_render_name"] = selected_recipient["name"]
        alert["primary_render_type"] = render_key
    else:
        alert["primary_render_name"] = ALL_RECIPIENTS["IT_ADMIN"]["name"]
        alert["primary_render_type"] = "IT_ADMIN"
    
    entity_map_by_id = {}
    entity_map_by_name = {}
    for e in alert.get("entities", []):
        if isinstance(e, dict):
            eid = e.get("id")
            name = e.get("name")
            if eid is not None: entity_map_by_id[str(eid)] = e
            if name is not None: entity_map_by_name[str(name)] = e
    alert["_entity_map_by_id"] = entity_map_by_id
    alert["_entity_map_by_name"] = entity_map_by_name
    alert["_entity_names"] = list(entity_map_by_name.keys())
    return alert

JINJA_VARIABLES = [
    "alert.primary_render_name", 
    "alert.primary_render_type", 
    "alert.user_names_emails", 
    "alert.alert_time_readable", 
    "alert.cities", 
    "alert.states", 
    "alert.countries", 
    "alert.principal_ips", 
    "alert.carriers", 
    "alert.applications", 
    "alert.user_agents", 
    "alert.login_statuses"
]

def get_alert_context_keys(render_field: str = "Manager") -> Dict[str, Any]:
    mock_siemplify = MockSiemplifyAction()
    signal_data_str = mock_siemplify.extract_action_param("signal_data", print_value=False)
    
    alert_data = json.loads(signal_data_str)
    alert_context = alert_data[0] if isinstance(alert_data, list) and alert_data else alert_data
    normalized_alert = normalize_alert(alert_context, render_field)

    keys_info = {}
    for key in JINJA_VARIABLES:
        try:
            top_key, *sub_keys = key.split('.')
            value = normalized_alert
            for sub in [top_key] + sub_keys:
                if isinstance(value, dict):
                    value = value.get(sub)
                elif isinstance(value, list) and sub.isdigit():
                    value = value[int(sub)]
                else:
                    value = "N/A"
            
            if isinstance(value, list):
                keys_info[key] = f"List (e.g., {value[:1]}...)"
            else:
                keys_info[key] = f"String (e.g., '{value}')"
        except Exception:
            keys_info[key] = "N/A"

    return keys_info

def convert_html_to_jinja_with_ai(html_content: str, variable_map: Dict[str, Any]) -> str:
    """Uses OpenRouter AI to convert HTML to a Jinja template."""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is missing. Please set it in Vercel Environment Variables.")
    
    variable_list_str = "\n".join([f"- **{{{{ {k} }}}}**: {v}" for k, v in variable_map.items()])

    system_prompt = (
        "You are an expert developer specializing in Flask and Jinja templating for security alerts. "
        "Your task is to convert a raw HTML template into a functional Jinja2 template. "
        "The HTML is for a security alert notification (e.g., 'Impossible Travel'). "
        "You must follow these steps strictly:\n"
        "1. **Identify** the appropriate HTML elements in the provided HTML to replace with the Jinja variables.\n"
        "2. **Use** the Jinja variables exactly as provided in the list below.\n"
        "3. **Use** Jinja filters where appropriate (e.g., `| join(', ')`, `| default('N/A')`).\n"
        "4. **Implement** the conditional logic for the salutation (`Dear {{ alert.primary_render_name }}...`) using the `alert.primary_render_type` variable, ensuring the conditional logic is preserved as given in the prompt.\n"
        "5. **Output ONLY THE FINAL JINJA2 TEMPLATE HTML** content, with no introductory text, explanations, or code fences. Ensure the template is well-formed HTML."
    )

    user_prompt = (
        "Below is the target HTML and the list of available Jinja variables. "
        "Convert the HTML into a Jinja template, inserting the variables correctly.\n\n"
        "**Target HTML:**\n"
        "```html\n"
        f"{html_content}\n"
        "```\n\n"
        "**Available Jinja Variables (all prefixed with `alert.`):**\n"
        f"{variable_list_str}\n\n"
        "Produce the final, complete Jinja2 template (HTML). NO EXPLANATIONS."
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-Title": "HTML to Jinja Converter"
    }
    data = {
        "model": "openai/gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    }

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=60
        )
        response.raise_for_status() 
        
        result = response.json()
        ai_output = result['choices'][0]['message']['content']
        return ai_output.strip()

    except requests.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code
        error_detail = http_err.response.text
        if status_code == 401:
             raise Exception(f"API Key Unauthorized (401). Check if OPENROUTER_API_KEY is correct.")
        raise Exception(f"OpenRouter API HTTP Error {status_code}: {error_detail}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network Error: Could not reach OpenRouter API. Details: {e}")
    except Exception as e:
        raise Exception(f"Conversion processing failed. Details: {e}")


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 


@app.route('/', methods=['GET'])
def index():
    """Renders the file upload form."""
    return render_template_string("""
    <!doctype html>
    <title>Flask Jinja Template Converter</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px; }
        input[type="submit"] { padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        input[type="submit"]:hover { background-color: #0056b3; }
    </style>
    <div class="container">
        <h1>Flask Jinja Template Converter</h1>
        <p>Upload your sample HTML file (e.g., <code>email_body.html</code>) to convert it into a fully functional Jinja template.</p>
        
        <form method="POST" action="/convert" enctype="multipart/form-data">
          <input type="file" name="html_file" id="html_file" accept=".html,.htm" required>
          <br><br>
          <input type="submit" value="Convert">
        </form>

        <hr>
        
        </div>
    """)

@app.route('/convert', methods=['POST'])
def convert():
    if 'html_file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['html_file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file:
        try:
            html_content = file.read().decode('utf-8')
        except Exception as e:
            return jsonify({"error": f"Error reading uploaded file: {e}"}), 400
    else:
        return jsonify({"error": "Invalid file upload"}), 400

    try:
        variable_map = get_alert_context_keys(render_field="Manager")

        jinja_template = convert_html_to_jinja_with_ai(html_content, variable_map)

        mock_siemplify = MockSiemplifyAction()
        signal_data_str = mock_siemplify.extract_action_param("signal_data", print_value=False)
        alert_data = json.loads(signal_data_str)
        alert_context = alert_data[0] if isinstance(alert_data, list) and alert_data else alert_data
        normalized_alert = normalize_alert(alert_context, render_field="Manager")
        
        env = Environment(autoescape=select_autoescape(['html', 'xml']), trim_blocks=True, lstrip_blocks=True)
        env.filters['safe_first'] = safe_first
        env.filters['iso_to_datetime'] = iso_to_datetime
        template = env.from_string(jinja_template)
        rendered_html = template.render(alert=normalized_alert)

        return render_template_string("""
            <!doctype html>
            <title>Conversion Result</title>
            <style>
                body { font-family: Arial, sans-serif; }
                .container { max-width: 1000px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px; }
                .download-btn { padding: 10px 20px; background-color: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 20px; }
                .download-btn:hover { background-color: #1e7e34; }
                pre { white-space: pre-wrap; background: #f4f4f4; padding: 10px; border: 1px solid #ddd; max-height: 400px; overflow: auto; }
                .preview { border: 2px solid #007bff; padding: 10px; margin-top: 15px; }
            </style>
            <div class="container">
                <h2>✅ Conversion Successful!</h2>
                <p>The input HTML file (<b>{{ filename }}</b>) was successfully converted into a Jinja template.</p>

                <form action="/download" method="POST" style="display: inline;">
                    <input type="hidden" name="template_content" value="{{ jinja_template | urlencode }}">
                    <button type="submit" class="download-btn">
                        Download converted_jinja_template.html
                    </button>
                </form>

                <h3>Generated Jinja Template:</h3>
                <pre>{{ jinja_template }}</pre>

                <h3>Rendered Output (Preview with Mock Data):</h3>
                <div class="preview">
                    {{ rendered_html | safe }}
                </div>
                <hr>
                <a href="/">Upload Another File</a>
            </div>
        """, 
        jinja_template=jinja_template, 
        rendered_html=rendered_html, 
        filename=file.filename)

    except Exception as e:
        error_message = str(e)
        return render_template_string("""
            <!doctype html>
            <title>Conversion Failed</title>
            <style>
                body { font-family: Arial, sans-serif; } 
                .error-box { max-width: 800px; margin: 50px auto; padding: 15px; border: 2px solid red; background-color: #fdd; border-radius: 8px; }
                .error-box pre { color: red; white-space: pre-wrap; background: #fce; padding: 10px; border: 1px solid #f99; }
            </style>
            <div class="error-box">
                <h2>❌ Conversion Failed!</h2>
                <p>An error occurred during the conversion process. This often means the HTML content was malformed or the **API Key is missing/incorrect**.</p>
                <pre>{{ error_message }}</pre>
                <hr>
                <a href="/">Go Back and Try Again</a>
            </div>
        """, error_message=error_message), 500

@app.route('/download', methods=['POST'])
def download_template():
    """Handles the download request by sending the template content."""
    template_content_encoded = request.form.get('template_content')
    if not template_content_encoded:
        return "Error: Template content not provided.", 400
    
    template_content = urllib.parse.unquote(template_content_encoded)
    
    str_io = io.BytesIO()
    str_io.write(template_content.encode('utf-8'))
    str_io.seek(0)
    
    return send_file(
        str_io,
        mimetype='text/html',
        as_attachment=True,
        download_name='converted_jinja_template.html'
    )


if __name__ == '__main__':
    if not os.environ.get("OPENROUTER_API_KEY"):
         print("WARNING: OPENROUTER_API_KEY environment variable not found. Conversion will only work locally if running via `python app.py`.")

    print("Running Flask app. Access http://127.0.0.1:5000/")
    app.run(debug=True)
