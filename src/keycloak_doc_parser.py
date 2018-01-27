from bs4 import BeautifulSoup
import requests
import re
from jinja2 import Template
import json

# This file will compile the keycloak online api documentation into a python sdk

url = "http://www.keycloak.org/docs-api/3.4/rest-api/index.html#_overview"
template_file = "./keycloak_sdk.py.j2"

endpoint_pattern = "(PUT|POST|GET|DELETE|OPTIONS)\s(.*)"

names = {}
with open("./wordlist.json") as f:
    names = json.load(f)


def lint_param_name(name):
    name = re.sub("-", "_", name)
    if name == "pass":
        name = "password"
    return name


def generate_function_name(name_id):
    word_list = [
        "clear", "all", "get", "set", "update", "delete", "management",
        "permission", "realm", "role", "mapping", "composite",
        "client", "create", "scope", "required", "push", "per", "mapper",
        "simple", "session", "send", "service", "remove", "to", "register",
        "generate", "add", "federated", "available", "entity", "by", "account",
        "and", "get", "application", "brute", "force", "user", "disble",
        "credential", "type", "key", "lower", "new", "events", "in", "id", "for"
    ]
    while name_id[0] == '_':
        name_id = name_id[1:]
    for word in word_list:
        name_id = re.sub(word, word + "_", name_id)
    while name_id[-1] == '_':
        name_id = name_id[0:-1]
    return name_id


def parse_ulist(html):
    rval = []
    items = html.find_all("li")
    for item in items:
        rval.append(item.code.string)
    return rval


def parse_table(html):
    rval = []
    headers = [el.string for el in html.table.thead.find_all("th")]
    rows = html.table.tbody.find_all("tr")
    for row in rows:
        entry = {}
        elements = row.find_all("td")
        for idx in range(0, len(elements)):
            key = headers[idx]
            if key == "Name":
                entry[key] = elements[idx].strong.string
                required = elements[idx].em.string
                if required:
                    entry["Required"] = (required == "required")
            else:
                val = elements[idx].string
                entry[key] = val
        rval.append(entry)
    return rval


def parse_endpoint(endpoint, context):
    output = {}
    output.update(context)
    output["name"] = endpoint.h4.string
    output["name_id"] = endpoint.h4.attrs.get("id", "")
    # output["name_py"] = generate_function_name(output["name_id"])
    match = re.match(endpoint_pattern, output["name"])
    if not match:
        output["help"] = output["name"]
        endpoint_desc = endpoint.find("div", "literalblock").pre.string
        match = re.match(endpoint_pattern, endpoint_desc)
    if match:
        output["method"] = match.groups()[0]
        output["endpoint"] = match.groups()[1]
        output["endpoint_nice"] = match.groups()[1]
    else:
        raise ValueError("Couldn't parse endpoint {}".format(endpoint_desc))
    sections = endpoint.find_all("div", "sect4")
    for section in sections:
        name = section.h5.string
        if name == "Parameters":
            output["parameters"] = parse_table(section)
            for param in output["parameters"]:
                # Also change endpoint...
                output["endpoint_nice"] = re.sub(
                    param["Name"],
                    lint_param_name(param["Name"]),
                    output["endpoint_nice"]
                )
                param["Name"] = lint_param_name(param["Name"])
        elif name == "Responses":
            output["responses"] = parse_table(section)
        elif name == "Consumes":
            output["produces"] = parse_ulist(section)
        elif name == "Produces":
            output["consumes"] = parse_ulist(section)
    output["name_py"] = names["map"][" ".join(
        [output["method"], output["endpoint"]])]
    return output


def parse_url(url):
    # Get the page
    api_endpoints = []
    response = requests.get(url)
    if not response.status_code == 200:
        response.raise_for_status()
    soup = BeautifulSoup(response.text)
    sections = soup.find_all("div", "sect1")
    for section in sections:
        header = section.h2.string
        if header == "Overview":
            pass
        elif header == "Resources":
            subsections = section.find_all("div", "sect2")
            for subsection in subsections:
                subheader = subsection.h3.string
                subheader_id = subsection.h3.attrs.get('id', None)
                endpoints = subsection.find_all("div", "sect3")
                context = {
                    "header": header,
                    "subheader": subheader,
                    "subheader_id": subheader_id,
                    "classname_py": names["map"][subheader]
                }
                for endpoint in endpoints:
                    api_endpoints.append(parse_endpoint(endpoint, context))
        elif header == "Definitions":
            # TODO: Parse me
            pass
    return api_endpoints

# File creation

#
# def write_func(endpoint, f, indent=0):
#     # Preamble
#     def put_lines(f, indent, lines):
#         for line in lines.split('\n'):
#             f.write("{}{}\n".format(" ".repeat(indent), line))
#     help_text = ""
#     # Gen function name
#     func_name_parts = re.split("\s+", re.findall(
#         "(.*)\s{2,}.*", endpoint["name"])[0])
#     func_name = "_".join([st.lower() for st in func_name_parts])
#     help_text = help_text + endpoint["name"] + "\n\n"
#
#     # Gen arguments
#     help_text = help_text + "Parameters\n----------\n"
#     check_lines = []
#     params = endpoint["parameters"]
#     for param in params:
#         help_text = help_text + "{} : {}\n    {}".format(
#             param["Name"], param["Schema"], param["Description"])
#         if param["Schema"] == "string":
#             check_lines = check_lines + "assert(isa({}, String))".format(
#                 param["Name"]
#             )
#         else:
#             raise ValueError("Unknown param type {}".format(param["Schema"]))
#
#     # Write function
#     put_lines(f, indent, "def {}({}):".format(
#         func_name, ", ".join([param["Name"] for param in params])
#     ))
#     indent = indent + 4
#     put_lines("\"\"\"{}\"\"\"".format(help_text))
#     put_lines("""return self.request(
#         method=\"{method}\",
#         endpoint=self._url(
#             \"{url}\".format(
#                 flowAlias=flow_name
#             )),
#         {data_param}data=data,
#     )""".format())

# TODO: FormData???
# FormData
# Input type checks...
# Default values


def build_module(endpoints, template_file, target_file):
    subheaders = []
    with open(template_file, "r") as f:
        template = Template(f.read())
    with open(target_file, "w") as f:
        clients = {}
        for endpoint in endpoints:
            sh = endpoint["classname_py"]
            if sh not in clients:
                clients[sh] = {
                    "endpoints": [],
                    "name": endpoint["subheader"]
                }
            clients[sh]["endpoints"].append(endpoint)

            # Prelim check
            if endpoint["subheader"] not in subheaders:
                # Print section heading
                subheaders.append(endpoint["subheader"])
        print("sections:")
        print(subheaders)

        # Write the function
        function_text = template.render(clients=clients)
        f.write(function_text.encode('utf8') + "\n\n")


if __name__ == "__main__":
    endpoints = parse_url(url)
    for ep in names["additional"]:
        endpoints.append(ep)
    build_module(endpoints, template_file, "./keycloak_sdk.py")
