import re
import os
import json
import logging
import concurrent.futures

import httpx

from .config import API_CONFIGS

logger = logging.getLogger('checkpoint_api')


def _get(url, headers=None, timeout=30):
    """Single GET via httpx. TLS verification honours ``config.VERIFY_SSL`` (read at call time so an
    env override is picked up), redirects are followed, matching the previous ``requests.get`` behaviour."""
    from .config import VERIFY_SSL
    return httpx.get(url, headers=headers, timeout=timeout, verify=VERIFY_SSL, follow_redirects=True)

def get_latest_api_version(api_type='management'):
    """
    Fetches the latest API version from Check Point's documentation.
    
    Args:
        api_type: 'management' or 'gaia'
    """
    if api_type not in API_CONFIGS:
        logger.warning(f"Unknown API type: {api_type}, defaulting to 'management'")
        api_type = 'management'
    
    config = API_CONFIGS[api_type]
    try:
        url = f"{config['base_url']}js/versions.js"
        logger.info(f"Attempting to discover latest {config['name']} version from {url}...")
        response = _get(url, timeout=10)
        response.raise_for_status()
        
        # Extract version using regex: var default_api_version = "v2.0.1";
        match = re.search(r'var\s+default_api_version\s*=\s*"([^"]+)"', response.text)
        if match:
            version = match.group(1)
            logger.info(f"Discovered latest {config['name']} version: {version}")
            return version
    except Exception as e:
        logger.warning(f"Failed to discover latest {config['name']} version: {e}")
    
    # Fallback if discovery fails
    fallback = config['fallback_version']
    logger.info(f"Using fallback {config['name']} version: {fallback}")
    return fallback

def fetch_data(api_type='management', api_version=None):
    logger.info("Starting fetch_data with CACHING enabled")
    if not api_version:
        api_version = get_latest_api_version(api_type)
    
    if api_type not in API_CONFIGS:
        logger.warning(f"Unknown API type: {api_type}, defaulting to 'management'")
        api_type = 'management'
    
    config = API_CONFIGS[api_type]
    base_url = f"{config['base_url']}data/{api_version}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Referer": f"{config['base_url']}?"
    }
    
    # Cache setup
    cache_dir = os.path.join(os.getcwd(), 'data', 'cache')
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{api_type}_{api_version}_examples.json")
    
    logger.info(f"Fetching {config['name']} data for version: {api_version}")
    logger.info("Fetching dynamic/apis.json...")
    apis_resp = _get(f"{base_url}/dynamic/apis.json", headers=headers)
    apis_resp.raise_for_status()
    apis_data = apis_resp.json()
    
    examples_data = {}
    
    # Try loading from cache first
    if os.path.exists(cache_file):
        logger.info(f"Loading examples from cache: {cache_file}")
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                examples_data = json.load(f)
            logger.info(f"Loaded {len(examples_data.get('examples', {}))} examples from cache")
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            examples_data = {} # Fallback to fetch
            
    # If not in cache, fetch them
    if not examples_data:
        # Try fetching standard examples.json first (works for Management API)
        logger.info("Fetching dynamic/examples.json...")
        try:
            examples_resp = _get(f"{base_url}/dynamic/examples.json", headers=headers)
            if examples_resp.status_code == 200:
                examples_data = examples_resp.json()
                logger.info(f"Loaded {len(examples_data.get('examples', {}))} examples from examples.json")
        except Exception as e:
            logger.warning(f"Error fetching examples.json: {e}")

    logger.info("Fetching static_content/apis.json...")
    static_resp = _get(f"{base_url}/static_content/apis.json", headers=headers)
    static_data = static_resp.json() if static_resp.status_code == 200 else {}

    logger.info("Fetching dynamic/content.json...")
    content_resp = _get(f"{base_url}/dynamic/content.json", headers=headers)
    content_data = content_resp.json() if content_resp.status_code == 200 else {}
    
    # If still no examples (e.g. GAiA API and not in cache), fetch external examples
    if not examples_data and content_data:
        logger.info("Searching for external examples in content.json...")
        external_examples = {}
        examples_to_fetch = []
        
        # Helper to find external data references
        def find_external_examples_refs(obj):
            if isinstance(obj, dict):
                if 'external-data' in obj and 'file-names' in obj['external-data']:
                    cmd_name = None
                    if 'name' in obj:
                        name_obj = obj['name']
                        if isinstance(name_obj, dict):
                            cmd_name = name_obj.get('web')
                        elif isinstance(name_obj, str):
                            cmd_name = name_obj
                    
                    if cmd_name:
                        files = obj['external-data']['file-names']
                        if files:
                            for i, file_path in enumerate(files):
                                # Clean up path (remove double slashes if any)
                                clean_path = file_path.replace('//', '/')
                                # Construct full URL
                                ex_url = f"{base_url}/dynamic/{clean_path}"
                                examples_to_fetch.append((cmd_name, ex_url, i))
                                
                for value in obj.values():
                    find_external_examples_refs(value)
            elif isinstance(obj, list):
                for item in obj:
                    find_external_examples_refs(item)

        find_external_examples_refs(content_data)
        
        if examples_to_fetch:
            logger.info(f"Found {len(examples_to_fetch)} external examples to fetch. Starting parallel download...")
            
            # Pooled, retrying httpx client (thread-safe — shared across the executor below).
            from .config import VERIFY_SSL
            session = httpx.Client(headers=headers, timeout=10, verify=VERIFY_SSL,
                                   follow_redirects=True,
                                   transport=httpx.HTTPTransport(retries=3),
                                   limits=httpx.Limits(max_connections=50, max_keepalive_connections=50))

            def fetch_single_example(item):
                cmd_name, url, index = item
                try:
                    resp = session.get(url)
                    if resp.status_code == 200:
                        ex_json = resp.json()
                        # Add command name if missing
                        if 'name' not in ex_json:
                            ex_json['name'] = f"{cmd_name} Example {index+1}"
                        return f"{cmd_name}/example_{index}", ex_json
                except Exception as e:
                    pass
                return None

            # Use ThreadPoolExecutor for parallel fetching
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_example = {executor.submit(fetch_single_example, item): item for item in examples_to_fetch}
                
                completed_count = 0
                total_count = len(examples_to_fetch)
                
                for future in concurrent.futures.as_completed(future_to_example):
                    result = future.result()
                    if result:
                        key, data = result
                        external_examples[key] = data
                    
                    completed_count += 1
                    if completed_count % 50 == 0 or completed_count == total_count:
                         logger.info(f"Fetched {completed_count}/{total_count} examples...")
            
            # Close session
            session.close()
        
        if external_examples:
            logger.info(f"Loaded {len(external_examples)} external examples from individual files")
            examples_data = {'examples': external_examples}
            
            # Save to cache
            try:
                logger.info(f"Saving examples to cache: {cache_file}")
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(examples_data, f)
            except Exception as e:
                logger.warning(f"Failed to save cache: {e}")

    return apis_data, examples_data, static_data, content_data

def fetch_documentation_page(api_type, api_version, page_name):
    """
    Fetches a specific HTML documentation page (e.g., changelog.html).
    
    Args:
        api_type: 'management' or 'gaia'
        api_version: e.g., 'v1.9'
        page_name: e.g., 'changelog.html'
        
    Returns:
        str: HTML content of the page body, or None if failed.
    """
    if not api_version:
        api_version = get_latest_api_version(api_type)
        
    if api_type not in API_CONFIGS:
        api_type = 'management'
        
    config = API_CONFIGS[api_type]
    base_url = f"{config['base_url']}data/{api_version}"
    
    # Cache setup
    cache_dir = os.path.join(os.getcwd(), 'data', 'cache')
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{api_type}_{api_version}_{page_name}")
    
    # Try cache first
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                logger.info(f"Loaded {page_name} from cache")
                return f.read()
        except Exception as e:
            logger.warning(f"Failed to read cache for {page_name}: {e}")
            
    # Fetch from remote
    url = f"{base_url}/{page_name}"
    logger.info(f"Fetching documentation page: {url}")
    
    try:
        response = _get(url, timeout=10)
        if response.status_code == 200:
            content = response.text
            
            # Extract body content if possible
            # Simple regex to get content between <body> tags
            body_match = re.search(r'<body[^>]*>(.*?)</body>', content, re.DOTALL | re.IGNORECASE)
            if body_match:
                content = body_match.group(1)
                
            # Clean up content
            # Remove the outer div if it exists (e.g. <div class="content-v1_8_1">)
            content = re.sub(r'^\s*<div[^>]*>(.*)</div>\s*$', r'\1', content, flags=re.DOTALL)
            
            # Replace <font face="Courier New"> with <code> tags for better styling
            content = re.sub(r'<font[^>]*face=["\']Courier New["\'][^>]*>(.*?)</font>', r'<code>\1</code>', content, flags=re.IGNORECASE)
            
            # Fix relative links to point to the correct place
            # This is tricky without a full HTML parser, but we can try basic fixes
            # e.g. href="some_page.html" -> href="#" (disable for now) or keep as is
            
            # Save to cache
            try:
                with open(cache_file, 'w', encoding='utf-8') as f:
                    f.write(content)
            except Exception as e:
                logger.warning(f"Failed to save cache for {page_name}: {e}")
                
            return content
        else:
            logger.warning(f"Failed to fetch {page_name}: Status {response.status_code}")
    except Exception as e:
        logger.error(f"Error fetching {page_name}: {e}")
        
    return None

def fetch_changes_json(api_type, api_version):
    """
    Fetches the changes.json file which contains structured changelog data.
    
    Args:
        api_type: 'management' or 'gaia'
        api_version: e.g., 'v1.9'
        
    Returns:
        dict: Parsed JSON content, or None if failed.
    """
    if not api_version:
        api_version = get_latest_api_version(api_type)
        
    if api_type not in API_CONFIGS:
        api_type = 'management'
        
    config = API_CONFIGS[api_type]
    base_url = f"{config['base_url']}data/{api_version}"
    
    # Cache setup
    cache_dir = os.path.join(os.getcwd(), 'data', 'cache')
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{api_type}_{api_version}_changes.json")
    
    # Try cache first
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                logger.info(f"Loaded changes.json from cache")
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read cache for changes.json: {e}")
            
    # Fetch from remote
    # Try dynamic/changes.json first
    urls = [
        f"{base_url}/dynamic/changes.json",
        f"{base_url}/changes.json"
    ]
    
    for url in urls:
        logger.info(f"Fetching changes data: {url}")
        try:
            response = _get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Save to cache
                try:
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f)
                except Exception as e:
                    logger.warning(f"Failed to save cache for changes.json: {e}")
                    
                return data
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            
    return None

