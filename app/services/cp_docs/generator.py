import re
import json
import logging
import shlex
from .config import API_CONFIGS, CHECKPOINT_SERVER_URL, GAIA_SERVER_URL, CHECKPOINT_API_VERSION, SHOW_UNDOCUMENTED
from .fetcher import get_latest_api_version, fetch_data
from .hierarchy import build_hierarchy_map
from .schema import build_schema_from_object

logger = logging.getLogger('checkpoint_api')

def parse_cli_request(cli_string, properties, command_prefix=None):
    """
    Attempts to parse a Check Point CLI command string into a JSON object 
    based on known properties.
    """
    try:
        # Use shlex to handle quoted strings correctly
        tokens = shlex.split(cli_string)
    except:
        return None
        


    # Strip command prefix
    if command_prefix:
        prefix_idx = 0
        token_idx = 0
        while prefix_idx < len(command_prefix) and token_idx < len(tokens):
             if tokens[token_idx].lower() == command_prefix[prefix_idx].lower():
                 token_idx += 1
                 prefix_idx += 1
             elif command_prefix[prefix_idx].lower() == 'mgmt_cli':
                 # Allow skipping mgmt_cli in prefix if not in tokens
                 prefix_idx += 1
             else:
                 # Mismatch, stop stripping
                 break
        
        tokens = tokens[token_idx:]


        
    result = {}
    
    i = 0
    while i < len(tokens):
        token = tokens[i]
        
        # Check if this token is a property name
        if token in properties:
            # The next token should be the value
            if i + 1 < len(tokens):
                val = tokens[i+1]
                result[token] = val
                i += 2
                continue
        
        # Check for --param value
        if token.startswith('--') and token[2:] in properties:
             prop = token[2:]
             if i + 1 < len(tokens):
                val = tokens[i+1]
                # Check if next token is another flag or command end
                if not val.startswith('--'):
                    result[prop] = val
                    i += 2
                    continue
                else:
                    # Boolean flag?
                    result[prop] = True
                    i += 1
                    continue
        
        i += 1
        
    return result if result else None


def convert_checkpoint_to_openapi(api_type='management', server_url=None, api_version=None, data_source=None):
    # Validate API type
    if api_type not in API_CONFIGS:
        logger.warning(f"Unknown API type: {api_type}, defaulting to 'management'")
        api_type = 'management'
    
    config = API_CONFIGS[api_type]
    
    # Use provided parameters or fall back to environment variables
    if not server_url:
        if api_type == 'management':
            server_url = CHECKPOINT_SERVER_URL
        elif api_type == 'gaia':
            server_url = GAIA_SERVER_URL
        else:
            server_url = config['default_server']
    
    api_version = api_version or CHECKPOINT_API_VERSION
    
    if data_source:
        apis_data = data_source.get('apis', {})
        examples_data = data_source.get('examples', {})
        static_data = data_source.get('static', {})
        content_data = data_source.get('content', {})
    else:
        # If still None (because env var was None), discover it
        if not api_version:
            api_version = get_latest_api_version(api_type)
        
        apis_data, examples_data, static_data, content_data = fetch_data(api_type, api_version)
    
    # Build hierarchy map and ordered tags
    hierarchy_map, ordered_tags = build_hierarchy_map(content_data)
    
    # Index objects by name for quick lookup
    objects_map = {}
    if 'objects' in apis_data and isinstance(apis_data['objects'], list):
        for obj in apis_data['objects']:
            key = obj.get('object-name', obj.get('name'))
            if key:
                objects_map[key] = obj

    # Index examples by command name
    examples_map = {}
    if 'examples' in examples_data and isinstance(examples_data['examples'], dict):
        for key, ex in examples_data['examples'].items():
            # Key format: "command/example-name" or just "command"
            cmd_name = None
            if '/' in key:
                cmd_name = key.split('/')[0]
            else:
                cmd_name = ex.get('name')
            
            if cmd_name:
                if cmd_name not in examples_map:
                    examples_map[cmd_name] = []
                examples_map[cmd_name].append(ex)

    openapi = {
        "openapi": "3.0.0",
        "info": {
            "title": f"Check Point {config['name']}",
            "version": api_version,
            "description": f"Auto-generated OpenAPI spec from Check Point {config['name']} documentation."
        },
        "servers": [
            {"url": server_url, "description": f"Check Point {config['name']} Server"}
        ],
        "components": {
            "securitySchemes": {
                "sessionId": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-chkp-sid",
                    "description": "Session ID obtained from login endpoint. Will be automatically populated after successful login."
                }
            }
        },
        "tags": [], # Will be populated after filtering
        "paths": {}
    }

    # Track which tags actually have commands
    used_tags = set()

    if 'commands' in apis_data:
        commands_list = apis_data['commands']
        if isinstance(commands_list, dict):
            commands_list = list(commands_list.values())

        for cmd in commands_list:
            # Extract basic info
            cmd_name = cmd.get('name', {}).get('web')
            if not cmd_name:
                continue

            # Skip AsyncRequest
            if cmd_name == 'AsyncRequest':
                continue
            
            # Filter out undocumented commands unless SHOW_UNDOCUMENTED is enabled
            is_documented = cmd.get('documented', True)  # Default to True if field is missing
            if not is_documented and not SHOW_UNDOCUMENTED:
                logger.debug(f"Skipping undocumented command: {cmd_name}")
                continue
                

            # Extract command info from 'name' object (where it seems to reside for GAiA)
            # or from top level if present
            command_obj = cmd.get('name', {}).get('command')
            if not command_obj:
                command_obj = cmd.get('command', {})
                
            web_cmd_str = command_obj.get('web', '')
            path_match = re.search(r'/web_api(/[\w-]+)', web_cmd_str)
            if path_match:
                path = path_match.group(1)
            else:
                path = f"/{cmd_name}"

            description = cmd.get('description', '')
            
            # Determine Tags from Hierarchy
            tags = ["Check Point API"] # Default
            
            category_path = hierarchy_map.get(cmd_name)
            if category_path:
                # Use only the top-level category as the tag for proper grouping
                # This ensures all "Session Management / *" endpoints are grouped under "Session Management"
                top_level_category = category_path[0]
                tags = [top_level_category]
            
            # Track which tags are actually used
            if tags and tags[0] != "Check Point API":
                used_tags.add(tags[0])

            

            # Extract valid CLI arguments
            cli_args = set()
            if 'arguments' in cmd:
                for arg in cmd['arguments']:
                    cli_args.add(arg.get('name'))

            # Build Request Body
            request_class = cmd.get('request')
            request_schema = {}
            if request_class and request_class in objects_map:
                request_schema = build_schema_from_object(objects_map[request_class], objects_map)

            # Build Response
            response_class = cmd.get('response', {}).get('on-success', {}).get('web', {}).get('object', {}).get('object-name')
            response_schema = {}

            if response_class and response_class in objects_map:
                response_schema = build_schema_from_object(objects_map[response_class], objects_map)

            # Find examples
            cmd_examples = examples_map.get(cmd_name, [])

            # Prepare command prefix tokens for CLI parsing
            command_prefix = []
            cli_cmd_str = command_obj.get('cli')
            if cli_cmd_str and cli_cmd_str != 'N/A':
                try:
                    cmd_tokens = shlex.split(cli_cmd_str)
                    # Filter out flags
                    command_prefix = [t for t in cmd_tokens if not t.startswith('-')]
                except:
                    pass

            operation = {
                "summary": description,
                "operationId": cmd_name,
                "tags": tags,
                "responses": {
                    "200": {
                        "description": "Successful operation",
                        "content": {
                            "application/json": {
                                "schema": response_schema
                            }
                        }
                    }
                }
            }
            
            # Add security requirement for all endpoints except login
            if cmd_name != "login":
                operation["security"] = [{"sessionId": []}]

            # Add Request Body
            if request_schema:
                operation["requestBody"] = {
                    "content": {
                        "application/json": {
                            "schema": request_schema
                        }
                    }
                }
            
            # Add Examples to Operation
            if cmd_examples:
                # Request Examples
                req_examples = {}
                res_examples = {}
                first_req_example = None  # Track the first example to set as default
                first_res_example = None
                
                for i, ex in enumerate(cmd_examples):
                    ex_name = f"Example {i+1}"
                    
                    if 'web' in ex:
                        web_ex = ex['web']
                        if 'request' in web_ex and 'body' in web_ex['request']:
                             try:
                                 parsed_req = json.loads(web_ex['request']['body'])
                                 req_examples[ex_name] = {"value": parsed_req}
                                 if first_req_example is None:
                                     first_req_example = parsed_req
                             except:
                                 # Try to parse as HTTP request (common in GAiA)
                                 raw_body = web_ex['request']['body']
                                 parsed_req = None
                                 
                                 try:
                                     # Split by double newline to separate headers from body
                                     parts = re.split(r'\r?\n\r?\n', raw_body, 1)
                                     if len(parts) > 1:
                                         json_part = parts[1]
                                         # Sometimes there are trailing newlines or comments
                                         # Try to find the first { and last }
                                         json_match = re.search(r'(\{.*\})', json_part, re.DOTALL)
                                         if json_match:
                                             json_part = json_match.group(1)
                                         
                                         parsed_req = json.loads(json_part)
                                         req_examples[ex_name] = {"value": parsed_req}
                                         if first_req_example is None:
                                             first_req_example = parsed_req
                                 except:
                                     pass
                                     
                                 if not parsed_req:
                                     # Try to parse CLI string to JSON using command arguments
                                     # Combine schema properties and CLI arguments
                                     props = set(request_schema.get('properties', {}).keys())
                                     props.update(cli_args)
                                     
                                     parsed_cli = parse_cli_request(raw_body, props, command_prefix)
                                     if parsed_cli:
                                         req_examples[ex_name] = {"value": parsed_cli}
                                         if first_req_example is None:
                                             first_req_example = parsed_cli
                                     else:
                                         req_examples[ex_name] = {"value": raw_body}
                                         if first_req_example is None:
                                             first_req_example = raw_body

                        if 'response' in web_ex and 'body' in web_ex['response']:
                             try:
                                 parsed_res = json.loads(web_ex['response']['body'])
                                 res_examples[ex_name] = {"value": parsed_res}
                                 if first_res_example is None:
                                     first_res_example = parsed_res
                             except:
                                 # Try to parse as HTTP response
                                 raw_body = web_ex['response']['body']
                                 try:
                                     # Split by double newline to separate headers from body (if any)
                                     parts = re.split(r'\r?\n\r?\n', raw_body, 1)
                                     if len(parts) > 1:
                                         json_part = parts[1]
                                         json_match = re.search(r'(\{.*\})', json_part, re.DOTALL)
                                         if json_match:
                                             json_part = json_match.group(1)
                                         
                                         parsed_res = json.loads(json_part)
                                         res_examples[ex_name] = {"value": parsed_res}
                                         if first_res_example is None:
                                             first_res_example = parsed_res
                                     else:
                                         # Maybe it's just a JSON string with some extra text around it?
                                         json_match = re.search(r'(\{.*\})', raw_body, re.DOTALL)
                                         if json_match:
                                             parsed_res = json.loads(json_match.group(1))
                                             res_examples[ex_name] = {"value": parsed_res}
                                             if first_res_example is None:
                                                 first_res_example = parsed_res
                                         else:
                                             res_examples[ex_name] = {"value": raw_body}
                                 except:
                                     res_examples[ex_name] = {"value": raw_body}

                    
                    elif 'cli' in ex:
                        # Fallback for GAiA which often only has CLI examples
                        cli_ex = ex['cli']
                        
                        # Request
                        if 'request' in cli_ex and 'body' in cli_ex['request']:
                            raw_body = cli_ex['request']['body']
                            try:
                                parsed_req = json.loads(raw_body)
                                req_examples[ex_name] = {"value": parsed_req}
                                if first_req_example is None:
                                    first_req_example = parsed_req
                            except:
                                # Try to parse CLI string to JSON
                                props = set(request_schema.get('properties', {}).keys())
                                props.update(cli_args)
                                
                                parsed_cli = parse_cli_request(raw_body, props, command_prefix)
                                
                                if parsed_cli:
                                    req_examples[ex_name] = {"value": parsed_cli}
                                    if first_req_example is None:
                                        first_req_example = parsed_cli
                                else:
                                    # Fallback to raw string
                                    req_examples[ex_name] = {"value": raw_body}
                                    if first_req_example is None:
                                        first_req_example = raw_body
                        
                        # Response
                        if 'response' in cli_ex and 'body' in cli_ex['response']:
                            raw_body = cli_ex['response']['body']
                            try:
                                parsed_res = json.loads(raw_body)
                                res_examples[ex_name] = {"value": parsed_res}
                                if first_res_example is None:
                                    first_res_example = parsed_res
                            except:
                                res_examples[ex_name] = {"value": raw_body}
                
                # Add examples to the operation
                if req_examples and 'requestBody' in operation:
                    operation['requestBody']['content']['application/json']['examples'] = req_examples
                    if first_req_example:
                        operation['requestBody']['content']['application/json']['schema']['example'] = first_req_example
                
                if res_examples:
                    operation['responses']['200']['content']['application/json']['examples'] = res_examples
                    if first_res_example:
                        operation['responses']['200']['content']['application/json']['schema']['example'] = first_res_example
            
            # Add to paths
            openapi['paths'][path] = {
                "post": operation
            }
            
    # Create a map of tag_name -> index in ordered_tags for sorting
    tag_sort_index = {}
    for i, t in enumerate(ordered_tags):
        tag_sort_index[t['name']] = i

    # Generate x-tag-groups for Redoc
    tag_groups = {}
    
    for tag_name in used_tags:
        parts = tag_name.split(' / ')
        top_level = parts[0]
        
        if top_level not in tag_groups:
            tag_groups[top_level] = set()
        tag_groups[top_level].add(tag_name)
            
    x_tag_groups = []
    
    sorted_groups = sorted(tag_groups.keys(), key=lambda x: tag_sort_index.get(x, 9999))
    
    for group_name in sorted_groups:
        tags_in_group = sorted(list(tag_groups[group_name]))
        x_tag_groups.append({
            "name": group_name,
            "tags": tags_in_group
        })
        
    openapi['x-tag-groups'] = x_tag_groups
    
    def get_tag_sort_key(tag_name):
        return (tag_sort_index.get(tag_name, 9999), tag_name)

    sorted_used_tags = sorted(list(used_tags), key=get_tag_sort_key)
    openapi['tags'] = [{"name": tag} for tag in sorted_used_tags]

    # Manually add login operation if it wasn't found
    if '/login' not in openapi['paths']:
        logger.info("Manually adding 'login' operation")
        openapi['paths']['/login'] = {
            "post": {
                "summary": "Log in to the server",
                "operationId": "login",
                "tags": ["Session"],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "user": {"type": "string"},
                                    "password": {"type": "string"},
                                    "api-key": {"type": "string"},
                                    "domain": {"type": "string"},
                                    "session-timeout": {"type": "integer"},
                                    "continue-session-in-timeout": {"type": "boolean"},
                                    "read-only": {"type": "boolean"}
                                }
                            },
                            "example": {
                                "user": "admin",
                                "password": "vpn123"
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "sid": {"type": "string"},
                                        "url": {"type": "string"},
                                        "uid": {"type": "string"},
                                        "session-timeout": {"type": "integer"},
                                        "last-login-was-at": {
                                            "type": "object",
                                            "properties": {
                                                "posix": {"type": "integer"},
                                                "iso-8601": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if not any(t['name'] == 'Session' for t in openapi['tags']):
            openapi['tags'].append({"name": "Session"})

    return openapi
