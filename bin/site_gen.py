import glob
import yaml
import argparse
import sys
import re
import requests
import json
import datetime
import xmltodict
from os import path, walk, remove
from jinja2 import Environment, FileSystemLoader
from stix2 import FileSystemSource
from stix2 import Filter
from pycvesearch import CVESearch
from tqdm import tqdm

CVESSEARCH_API_URL = 'https://cve.circl.lu'
SPLUNKBASE_API_URL = "https://apps.splunk.com/api/apps/entriesbyid/"
ATTACK_TACTICS_KILLCHAIN_MAPPING = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Weaponization",
    "Initial Access": "Delivery",
    "Execution": "Installation",
    "Persistence": "Installation",
    "Privilege Escalation": "Exploitation",
    "Defense Evasion": "Exploitation",
    "Credential Access": "Exploitation",
    "Discovery": "Exploitation", 
    "Lateral Movement": "Exploitation",
    "Collection": "Exploitation",
    "Command and Control": "Command and Control",
    "Command And Control": "Command and Control",
    "Exfiltration": "Actions On Objectives",
    "Impact": "Actions On Objectives"
}

def get_cve_enrichment_new(cve_id):
    cve_enriched = dict()
    cve_enriched['id'] = cve_id

    try: 
        cve = CVESearch(CVESSEARCH_API_URL)
        result = cve.id(cve_id)
        if result is None:
            print("Error getting CVE info for {0}".format(cve_id))
        else:
            cve_enriched['cvss'] = result['cvss']
            cve_enriched['summary'] = result['summary']
    except requests.exceptions.JSONDecodeError as exc:
        print(exc)
        print("Error getting CVE info for {0}".format(cve_id))

    return cve_enriched

def get_all_techniques(projects_path):
    path_cti = path.join(projects_path,'enterprise-attack')
    fs = FileSystemSource(path_cti)
    all_techniques = get_techniques(fs)
    return all_techniques

def get_techniques(src):
    filt = [Filter('type', '=', 'attack-pattern')]
    return src.query(filt)

def mitre_attack_object(technique, attack):
    mitre_attack = dict()
    mitre_attack['technique_id'] = technique["external_references"][0]["external_id"]
    mitre_attack['technique'] = technique["name"]

    # process tactics
    tactics = []
    if 'kill_chain_phases' in technique:
        for tactic in technique['kill_chain_phases']:
            if tactic['kill_chain_name'] == 'mitre-attack':
                tactic = tactic['phase_name'].replace('-', ' ')
                tactics.append(tactic.title())

    mitre_attack['tactic'] = tactics
    return mitre_attack

def get_mitre_enrichment_new(attack, mitre_attack_id):
    for technique in attack:
        if mitre_attack_id == technique["external_references"][0]["external_id"]:
            mitre_attack = mitre_attack_object(technique, attack)
            return mitre_attack
    return []

def enrich_datamodel(detection):
    detection["datamodel"] = []
    data_models = [
        "Authentication", 
        "Change", 
        "Change_Analysis", 
        "Email", 
        "Endpoint", 
        "Network_Resolution", 
        "Network_Sessions", 
        "Network_Traffic", 
        "Risk", 
        "Splunk_Audit", 
        "UEBA", 
        "Updates", 
        "Vulnerabilities", 
        "Web"
    ]
    for data_model in data_models:
        if data_model in detection["search"]:
            detection["datamodel"].append(data_model)

    return detection

def enrich_cis(detection):
    if detection["tags"]["security_domain"] == "network":
        detection["tags"]["cis20"] = ["CIS 13"]
    else:
        detection["tags"]["cis20"] = ["CIS 10"]
    return detection

def enrich_nist(detection):
    if detection["type"] == "TTP":
        detection["tags"]["nist"] = ["DE.CM"]
    else:
        detection["tags"]["nist"] = ["DE.AE"]
    return detection

def enrich_kill_chain(detection):
    kill_chain_phases = list()
    if "mitre_attacks" in detection:
        for mitre_attack_obj in detection["mitre_attacks"]:
            for tactic in mitre_attack_obj["tactic"]:
                kill_chain_phases.append(ATTACK_TACTICS_KILLCHAIN_MAPPING[tactic])
        detection["tags"]["kill_chain_phases"] = list(dict.fromkeys(kill_chain_phases))
    return detection

def enrich_splunk_app(splunk_ta):   
    appurl = SPLUNKBASE_API_URL + splunk_ta
    splunk_app_enriched = dict()
    try:
        response = requests.get(appurl)
        response_dict = xmltodict.parse(response.content)
        # check if list since data changes depending on answer
        url, results = parse_splunkbase_response(response_dict)
        # grab the app name
        for i in results:
            if i['@name'] == 'appName':
                splunk_app_enriched['name'] = i['#text']
        # grab out the splunkbase url  
        if 'entriesbyid' in url:
            response = requests.get(url)
            response_dict = xmltodict.parse(response.content)
            #print(json.dumps(response_dict, indent=2))
            url, results = parse_splunkbase_response(response_dict)
            # chop the url so we grab the splunkbase portion but not direct download
            splunk_app_enriched['url'] = url.rsplit('/', 4)[0]
    except requests.exceptions.ConnectionError as connErr:
        # there was a connection error lets just capture the name
        splunk_app_enriched['name'] = splunk_ta
        splunk_app_enriched['url'] = ''

    return splunk_app_enriched

def parse_splunkbase_response(response_dict):
    if isinstance(response_dict['feed']['entry'], list):
        url = response_dict['feed']['entry'][0]['link']['@href']
        results = response_dict['feed']['entry'][0]['content']['s:dict']['s:key']
    else:
        url = response_dict['feed']['entry']['link']['@href']
        results = response_dict['feed']['entry']['content']['s:dict']['s:key']
    return url, results
        

def add_macros(detection, REPO_PATH, macros): 
    # process macro yamls
    
    # match those in the detection
    macros_found = re.findall(r'`([^\s]+)`', detection['search'])
    macros_filtered = set()
    detection['macros'] = []

    for macro in macros_found:
        if not '_filter' in macro and not 'drop_dm_object_name' in macro:
            start = macro.find('(')
            if start != -1:
                macros_filtered.add(macro[:start])
            else:
                macros_filtered.add(macro)

    for macro_name in macros_filtered:
        for macro in macros:
            if macro_name == macro['name']:
                detection['macros'].append(macro)

    macro = dict()
    name = detection['name'].replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter'
    macro['name'] = name
    macro['definition'] = 'search *'
    macro['description'] = 'Update this macro to limit the output results to filter out false positives.'
    detection['macros'].append(macro)

    return detection


def add_lookups(detection, REPO_PATH, lookups):
    # process lookup yamls

    lookups_found = re.findall(r'lookup (?:update=true)?(?:append=t)?\s*([^\s]*)', detection['search'])
    detection['lookups'] = []
    for lookup_name in lookups_found:
        for lookup in lookups:
            if lookup['name'] == lookup_name:
                detection['lookups'].append(lookup)

    return detection

def add_splunk_app(detection):
    splunk_app_enrichment = []
    if 'supported_tas' in detection['tags']:
        for splunk_app in detection['tags']['supported_tas']:
            splunk_app_enrichment.append(enrich_splunk_app(splunk_app))
    detection['splunk_app_enrichment'] = splunk_app_enrichment

    return detection


def generate_doc_stories(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, types, attack, sorted_detections, sorted_playbooks, messages, VERBOSE):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + 'stories'):
        for file in files:
            if file.endswith(".yml") and 'security_content/stories/deprecated' != root:
                manifest_files.append((path.join(root, file)))

    stories = []
    for manifest_file in tqdm(manifest_files):
        story_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.load_all(stream=stream, Loader=yaml.CLoader))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)
        story_yaml = object
        stories.append(story_yaml)
    sorted_stories = sorted(stories, key=lambda i: i['name'])

    # enrich stories with information from detections: data_models, mitre_ids, kill_chain_phases
    sto_to_data_models = {}
    sto_to_mitre_attack_ids = {}
    sto_to_mitre_attacks = {}
    sto_to_kill_chain_phases = {}
    sto_to_det = {}
    for detection in sorted_detections:
        if 'analytic_story' in detection['tags']:
            for story in detection['tags']['analytic_story']:
                if story in sto_to_det.keys():
                    sto_to_det[story]['detections'].append(detection)
                else:
                    sto_to_det[story] = {}
                    sto_to_det[story]['detections'] = []
                    sto_to_det[story]['detections'].append(detection)

                data_model = detection['datamodel']
                if data_model:
                    for d in data_model:
                        if story in sto_to_data_models.keys():
                            sto_to_data_models[story].add(d)
                        else:
                            sto_to_data_models[story] = {d}

                if 'mitre_attack_id' in detection['tags']:
                    if story in sto_to_mitre_attack_ids.keys():
                        for mitre_attack_id in detection['tags']['mitre_attack_id']:
                            sto_to_mitre_attack_ids[story].add(mitre_attack_id)
                    else:
                        sto_to_mitre_attack_ids[story] = set(detection['tags']['mitre_attack_id'])

                if 'kill_chain_phases' in detection['tags']:
                    if story in sto_to_kill_chain_phases.keys():
                        for kill_chain in detection['tags']['kill_chain_phases']:
                            sto_to_kill_chain_phases[story].add(kill_chain)
                    else:
                        sto_to_kill_chain_phases[story] = set(detection['tags']['kill_chain_phases'])

                if 'mitre_attacks' in detection:
                        sto_to_mitre_attacks[story] = detection['mitre_attacks']

    playbook_types = list()
    playbook_use_cases = list()
    playbook_categories = list()
    playbook_apps = list()
    for playbook in sorted_playbooks:
        playbook_types.append(playbook["type"])
        if "use_cases" in playbook["tags"]:
            playbook_use_cases.extend(playbook["tags"]["use_cases"])
        if "defend_enriched" in playbook["tags"]:
            for item in range(0, len(playbook["tags"]["defend_enriched"])):
                playbook_categories.append(playbook["tags"]["defend_enriched"][item].get('category'))
        if "app_list" in playbook:
            playbook_apps.extend(playbook["app_list"])

    playbook_types = list(set(playbook_types))
    playbook_use_cases = list(set(playbook_use_cases))
    playbook_categories = list(set(playbook_categories))
    playbook_apps = list(set(playbook_apps))

    # add the enrich objects to the story
    for story in sorted_stories:
        story['detections'] = sto_to_det[story['name']]['detections']
        if story['name'] in sto_to_data_models:
            story['data_models'] = sorted(sto_to_data_models[story['name']])
        if story['name'] in sto_to_mitre_attack_ids:
            story['mitre_attack_ids'] = sorted(sto_to_mitre_attack_ids[story['name']])
        if story['name'] in sto_to_mitre_attacks:
            story['mitre_attacks'] = sto_to_mitre_attacks[story['name']]
        if story['name'] in sto_to_kill_chain_phases:
            story['kill_chain_phases'] = sorted(sto_to_kill_chain_phases[story['name']])

    # sort stories into categories
    # grab all the categories first 
    categories = []
    category_names = set()
    for story in sorted_stories:
        if 'category' in story['tags']:
            for category in story['tags']['category']:    
                category_names.add(category)

    # build an category object with stories to populate
    for category_name in sorted(category_names):
        new_category = {}
        new_category['name'] = category_name
        new_category['stories'] = []
        categories.append(new_category)

    # this is ugly :-(, go through each story, find matching categories
    # add it to our newly minted category object
    for story in sorted_stories:
        for category in categories:
            if 'category' in story['tags']:
                for c in story['tags']['category']:    
                    if category['name'] == c:
                        category['stories'].append(story)

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH), # nosemgrep
                             trim_blocks=False)

    # write detection navigation
    # first collect datamodels and tactics
    datamodels = []
    tactics = []
    for detection in sorted_detections:
        data_model = detection['datamodel']
        if data_model:
            for d in data_model:
                if d not in datamodels:
                    datamodels.append(d)
        if 'mitre_attacks' in detection:
            for attack in detection['mitre_attacks']:
                for t in attack['tactic']:
                    if t not in tactics:
                        tactics.append(t)

    template = j2_env.get_template('doc_navigation.j2')
    output_path = path.join(OUTPUT_DIR + '/_data/navigation.yml')
    output = template.render(
        types=types, 
        tactics=sorted(tactics), 
        datamodels=sorted(datamodels), 
        categories=sorted(category_names),
        playbook_types = sorted(playbook_types),
        playbook_use_cases = sorted(playbook_use_cases),
        playbook_categories = sorted(playbook_categories),
        playbook_apps = sorted(playbook_apps),
    )
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote navigation.yml structure to: {0}".format(output_path))

    # write navigation _pages

    # for datamodels
    template = j2_env.get_template('doc_navigation_pages.j2')
    for datamodel in sorted(datamodels):
        output_path = path.join(OUTPUT_DIR + '/_pages/' + datamodel.lower().replace(" ", "_") + ".md")
        output = template.render(tag=datamodel)
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, datamodel))

    # for tactics
    for tactic in sorted(tactics):
        output_path = path.join(OUTPUT_DIR + '/_pages/' + tactic.lower().replace(" ", "_") + ".md")
        output = template.render(tag=tactic)
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, tactic))

    # type page
    template = j2_env.get_template('doc_types_page.j2')
    output_path = path.join(OUTPUT_DIR + '/_pages/types.md')
    output = template.render(types=types)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, 'types.md'))

    # for types 
    template = j2_env.get_template('doc_navigation_type_pages.j2')
    for type in types:
        output_path = path.join(OUTPUT_DIR + '/_pages/' + type.lower() + "_type.md")
        output = template.render(type=type, detections=sorted_detections)
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, type))

    # for story categories
    template = j2_env.get_template('doc_navigation_story_pages.j2')
    for category in categories:
        output_path = path.join(OUTPUT_DIR + '/_pages/' + category['name'].lower().replace(" ", "_") + ".md")
        output = template.render(category=category)
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {0} structure to: {1}".format(category['name'], output_path))

    # write stories listing markdown
    template = j2_env.get_template('doc_story_page.j2')
    output_path = path.join(OUTPUT_DIR + '/_pages/stories.md')
    output = template.render(stories=sorted_stories)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote _pages for story to: {0}".format(output_path))

    # write stories markdown
    template = j2_env.get_template('doc_stories.j2')
    for story in sorted_stories:
        file_name = story['name'].lower().replace(" ","_") + '.md'
        output_path = path.join(OUTPUT_DIR + '/_stories/' + file_name)
        output = template.render(story=story, time=datetime.datetime.now())
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("doc_gen.py wrote {0} story documentation in markdown to: {1}".format(len(sorted_stories),OUTPUT_DIR + '/_stories/'))

    return sorted_stories, messages


def generate_doc_detections(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, types, attack, messages, VERBOSE, SKIP_ENRICHMENT):

    # Load lookups once
    lookup_manifest_files = []
    for root, dirs, files in walk(REPO_PATH + 'lookups'):
        for file in files:
            if file.endswith(".yml"):
                lookup_manifest_files.append((path.join(root, file)))

    lookups = []
    for lookup_manifest_file in lookup_manifest_files:
        lookup_yaml = dict()
        with open(lookup_manifest_file, 'r') as stream:
            try:
                object = list(yaml.load_all(stream=stream, Loader=yaml.CLoader))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)
        lookups.append(object)

    macro_manifest_files = []
    for root, dirs, files in walk(REPO_PATH + 'macros'):
        for file in files:
            if file.endswith(".yml"):
                macro_manifest_files.append((path.join(root, file)))

    # Load Macros once
    macros = []
    for macro_manifest_file in macro_manifest_files:
        macro_yaml = dict()
        with open(macro_manifest_file, 'r') as stream:
            try:
                object = list(yaml.load_all(stream=stream, Loader=yaml.CLoader))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)
        macro_yaml = object


        macros.append(macro_yaml)
    
    # Load detections
    manifest_files = []
    for t in types:
        for root, dirs, files in walk(REPO_PATH + 'detections/' + t):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))

        for root, dirs, files in walk(REPO_PATH + 'ssa_detections/' + t):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))        

    detections = []
    for manifest_file in tqdm(manifest_files):
        detection_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.load_all(stream=stream, Loader=yaml.CLoader))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)
        detection_yaml = object

        if "Splunk Behavioral Analytics" in detection_yaml["tags"]["product"]:
            if detection_yaml["status"] != "production":
                continue

        if detection_yaml["status"] == "experimental":
            detection_yaml['experimental'] = True

        # add macros
        detection_yaml = add_macros(detection_yaml, REPO_PATH, macros)

        # add lookups
        detection_yaml = add_lookups(detection_yaml, REPO_PATH, lookups)

        detection_yaml = enrich_datamodel(detection_yaml)

        detection_yaml = enrich_cis(detection_yaml)
        detection_yaml = enrich_nist(detection_yaml)
        

        # enrich the mitre object
        mitre_attacks = []
        if 'mitre_attack_id' in detection_yaml['tags']:
            for mitre_technique_id in detection_yaml['tags']['mitre_attack_id']:
                mitre_attack = get_mitre_enrichment_new(attack, mitre_technique_id)
                mitre_attacks.append(mitre_attack)
            detection_yaml['mitre_attacks'] = mitre_attacks

        detection_yaml = enrich_kill_chain(detection_yaml)

        if SKIP_ENRICHMENT == False:
            if VERBOSE:
                print("Info CVE and splunk app enrichment for detection {0}".format(detection_yaml['name']))
            # enrich support_tas
            detection_yaml = add_splunk_app(detection_yaml)

            # enrich the cve object
            cves = []
            if 'cve' in detection_yaml['tags']:
                for cve_id in detection_yaml['tags']['cve']:
                    cve = get_cve_enrichment_new(cve_id)
                    cves.append(cve)
                detection_yaml['cve'] = cves
        else:
            print("Info skipping CVE and splunk app enrichment for detection {0}".format(detection_yaml['name']))

        # grab the kind
        detection_yaml['kind'] = manifest_file.split('/')[-2]

        # check if is experimental, add the flag
        # if detection_yaml["status"] == "experimental":
        #     detection_yaml['experimental'] = True
    
        # check if is deprecated, add the flag
        if "deprecated" == manifest_file.split('/')[2]:
            detection_yaml['deprecated'] = True

        # skip baselines and Investigation
        if detection_yaml['type'] == 'Baseline' or detection_yaml['type'] == 'Investigation':
            continue
        else:
            detections.append(detection_yaml)

    sorted_detections = sorted(detections, key=lambda i: i['name'])

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH), # nosemgrep
                             trim_blocks=False, autoescape=True)

    # write markdown
    template = j2_env.get_template('doc_detections.j2') 
    for detection in sorted_detections:
        file_name = detection['date'] + "-" + detection['id'].lower() + '.md'
        output_path = path.join(OUTPUT_DIR + '/_posts/' + file_name)
        output = template.render(detection=detection, time=datetime.datetime.now())
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("doc_gen.py wrote {0} detections documentation in markdown to: {1}".format(len(sorted_detections),OUTPUT_DIR + '/_posts/'))

    # write markdown detection page
    template = j2_env.get_template('doc_detection_page.j2')
    output_path = path.join(OUTPUT_DIR + '/_pages/detections.md')
    output = template.render(detections=sorted_detections, time=datetime.datetime.now())
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote detections.md page to: {0}".format(output_path))

    return sorted_detections, messages

def generate_doc_playbooks(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, sorted_detections, messages, VERBOSE):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + 'playbooks/'):
        for file in files:
            if file.endswith(".yml"):
                manifest_files.append((path.join(root, file)))

    playbooks = []

    url = "https://d3fend.mitre.org/api/matrix.json"
    response = requests.get(url)
    if response.status_code == 200:
        defend_data_dict = response.json()
    else:
        print(f"Failed to fetch data. HTTP Status Code: {response.status_code}")
        sys.exit(1)


    for manifest_file in tqdm(manifest_files):
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.load_all(stream=stream, Loader=yaml.CLoader))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)

        enrich_mitre_defend(object, defend_data_dict)
        playbooks.append(object)

    sorted_playbooks = sorted(playbooks, key=lambda i: i['name'])

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH), # nosemgrep
                             trim_blocks=False, autoescape=True)

    # write markdown
    template = j2_env.get_template('doc_playbooks.j2')
    for playbook in sorted_playbooks:
        file_name = playbook['name'].lower().replace(" ","_") + '.md'
        output_path = path.join(OUTPUT_DIR + '/_playbooks/' + file_name)
        output = template.render(playbook=playbook, detections=sorted_detections, time=datetime.datetime.now())
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("doc_gen.py wrote {0} playbook documentation in markdown to: {1}".format(len(sorted_playbooks),OUTPUT_DIR + '/_playbooks/'))

    # write navigation pages
    playbook_types = list()
    playbook_use_cases = list()
    playbook_categories = list()
    playbook_apps = list()
    for playbook in sorted_playbooks:
        playbook_types.append(playbook["type"])
        if "use_cases" in playbook["tags"]:
            playbook_use_cases.extend(playbook["tags"]["use_cases"])
        if "defend_enriched" in playbook["tags"]:
            for item in range(0, len(playbook["tags"]["defend_enriched"])):
                playbook_categories.append(playbook["tags"]["defend_enriched"][item].get('category'))
        if "app_list" in playbook:
            playbook_apps.extend(playbook["app_list"])

    playbook_types = list(set(playbook_types))
    playbook_use_cases = list(set(playbook_use_cases))
    playbook_categories = list(set(playbook_categories))
    playbook_apps = list(set(playbook_apps))

    template = j2_env.get_template('doc_navigation_playbook_pages.j2') 
    for playbook_type in playbook_types:
        filtered_playbooks = list()
        for playbook in sorted_playbooks:
            if playbook["type"] == playbook_type:
                filtered_playbooks.append(playbook)
        
        output_path = path.join(OUTPUT_DIR + '/_pages/' + playbook_type.lower().replace(" ", "_") + ".md")
        output = template.render(
            category=playbook_type,
            playbooks=filtered_playbooks,
        )
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, playbook_type))

    for use_case in playbook_use_cases:
        filtered_playbooks = list()
        for playbook in sorted_playbooks:
            if "use_cases" in playbook["tags"]:
                if use_case in playbook["tags"]["use_cases"]:
                    filtered_playbooks.append(playbook)
        
        output_path = path.join(OUTPUT_DIR + '/_pages/' + use_case.lower().replace(" ", "_") + "playbook.md")
        output = template.render(
            category=use_case,
            playbooks=filtered_playbooks,
        )
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, use_case))

    for category in playbook_categories:
        filtered_playbooks = list()
        for playbook in sorted_playbooks:
            if "defend_enriched" in playbook["tags"]:
                for item in range(0, len(playbook["tags"]["defend_enriched"])):
                    if playbook["tags"]["defend_enriched"][item].get('category') == category:
                        filtered_playbooks.append(playbook)
        
        output_path = path.join(OUTPUT_DIR + '/_pages/' + category.lower().replace(" ", "_") + ".md")
        output = template.render(
            category=category,
            playbooks=filtered_playbooks,
        )
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, category))

    for app in playbook_apps:
        filtered_playbooks = list()
        for playbook in sorted_playbooks:
            if "app_list" in playbook:
                if app in playbook["app_list"]:
                    filtered_playbooks.append(playbook)
        
        output_path = path.join(OUTPUT_DIR + '/_pages/' + app.lower().replace(" ", "_") + ".md")
        output = template.render(
            category=app,
            playbooks=filtered_playbooks,
        )
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, app))

    # write markdown detection page
    template = j2_env.get_template('doc_playbooks_page.j2')
    output_path = path.join(OUTPUT_DIR + '/_pages/playbooks.md')
    output = template.render(playbooks=sorted_playbooks, detections=sorted_detections, time=datetime.datetime.now())
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote playbooks.md page to: {0}".format(output_path))

    return sorted_playbooks, messages


def enrich_mitre_defend(playbook, defend_data_dict):

    defend_enriched_list = []
    if "defend_technique_id" in playbook["tags"]:
        for id in playbook["tags"]["defend_technique_id"]:
            for tactic in defend_data_dict:
                for technique in tactic["children"]:
                    for defend_technique in technique["children"]:
                        if defend_technique["d3f:d3fend-id"] == id:
                            defend_enriched_list.append({"id": id, "technique": defend_technique["rdfs:label"], "definition": defend_technique["d3f:definition"], "category": technique["rdfs:label"]})
                        elif 'children' in defend_technique:
                            for sub_defend_technique in defend_technique["children"]:
                                if sub_defend_technique["d3f:d3fend-id"] == id:
                                    defend_enriched_list.append({"id": id, "technique": sub_defend_technique["rdfs:label"], "definition": defend_technique["d3f:definition"],"category": technique["rdfs:label"]})
     
    playbook["tags"]["defend_enriched"] = defend_enriched_list

def generate_doc_index(OUTPUT_DIR, TEMPLATE_PATH, sorted_detections, sorted_stories, sorted_playbooks, messages, VERBOSE):

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH), # nosemgrep
                             trim_blocks=False, autoescape=True)

    # write index updated metrics
    template = j2_env.get_template('doc_index.j2')
    output_path = path.join(OUTPUT_DIR + '/index.markdown')
    output = template.render(detection_count=len(sorted_detections), story_count=len(sorted_stories), playbook_count=len(sorted_playbooks))
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote site index page to: {0}".format(output_path))

    return messages


def wipe_old_folders(OUTPUT_DIR, VERBOSE):
    
    if VERBOSE:
        print("wiping the {0}/_posts/* folder".format(OUTPUT_DIR))

    try:
        for root, dirs, files in walk(OUTPUT_DIR + '/_posts/'):
            for file in files:
                if file.endswith(".md"):
                    remove(OUTPUT_DIR + '/_posts/' + file)
    except OSError as e:
        print("error: %s : %s" % (file, e.strerror))
        sys.exit(1)

    if VERBOSE:
        print("wiping the {0}/_stories/* folder".format(OUTPUT_DIR))

    try:
        for root, dirs, files in walk(OUTPUT_DIR + '/_stories/'):
            for file in files:
                if file.endswith(".md"):
                    remove(OUTPUT_DIR + '/_stories/' + file)
    except OSError as e:
        print("error: %s : %s" % (file, e.strerror))
        sys.exit(1)

    if VERBOSE:
        print("wiping the {0}/_playbooks/* folder".format(OUTPUT_DIR))

    try:
        for root, dirs, files in walk(OUTPUT_DIR + '/_playbooks/'):
            for file in files:
                if file.endswith(".md"):
                    remove(OUTPUT_DIR + '/_playbooks/' + file)
    except OSError as e:
        print("error: %s : %s" % (file, e.strerror))
        sys.exit(1)


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates documentation from Splunk Security Content", epilog="""
    This generates documention in the form of jekyll site research.splunk.com from Splunk Security Content yamls. """)
    parser.add_argument("-security_content_path", "--spath", required=False, default='security_content/', help="path to security_content repo")
    parser.add_argument("-cti_path", "--cpath", required=False, default='cti/', help="path to cti repo")
    parser.add_argument("-o", "--output", required=False, default='.', help="path to the output directory for the docs")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    parser.add_argument("-s", "--skip_enrichment", required=False, choices=('True','False'), default=False, help="skips app and cve enrichments")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.spath
    CTI_PATH = args.cpath
    OUTPUT_DIR = args.output
    VERBOSE = args.verbose
    SKIP_ENRICHMENT= args.skip_enrichment

    if not (path.isdir(REPO_PATH) or path.isdir(REPO_PATH)):
        print("error: {0} is not a directory".format(REPO_PATH))
        sys.exit(1)

    TEMPLATE_PATH = path.join('bin/jinja2_templates')

    if VERBOSE:
        print("getting mitre enrichment data from cti")
    techniques = get_all_techniques(CTI_PATH)

    wipe_old_folders(OUTPUT_DIR, VERBOSE)

    # detection categories
    types = ["endpoint", "application", "cloud", "network", "web", "experimental", "deprecated"]
    messages = []
    print("processing detections")
    sorted_detections, messages = generate_doc_detections(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, types, techniques, messages, VERBOSE, SKIP_ENRICHMENT)
    print("processing playbooks")
    sorted_playbooks, messages = generate_doc_playbooks(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, sorted_detections, messages, VERBOSE)
    print("processing stories")
    sorted_stories, messages = generate_doc_stories(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, types, techniques, sorted_detections, sorted_playbooks, messages, VERBOSE)
    messages = generate_doc_index(OUTPUT_DIR, TEMPLATE_PATH, sorted_detections, sorted_stories, sorted_playbooks, messages, VERBOSE)

    # print all the messages from generation
    for m in messages:
        print(m)
    print("finished successfully!")
