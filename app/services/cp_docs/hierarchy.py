def build_hierarchy_map(content_data):
    command_map = {}
    ordered_tags = []
    
    def traverse(chapters, path=[]):
        for chap in chapters:
            current_name = chap.get('name', 'Unnamed')
            
            # Add to ordered tags (capture all levels to preserve order)
            # Store the full path name to ensure uniqueness and correct order
            full_tag_name = " / ".join(path + [current_name])
            if full_tag_name not in [t['name'] for t in ordered_tags]:
                ordered_tags.append({"name": full_tag_name, "description": ""})
            
            current_path = path + [current_name]
            
            # Check commands
            if 'commands' in chap:
                for cmd in chap['commands']:
                    name_obj = cmd.get('name')
                    cmd_name = None
                    if isinstance(name_obj, dict):
                        cmd_name = name_obj.get('web')
                    elif isinstance(name_obj, str):
                        cmd_name = name_obj
                        
                    if cmd_name and isinstance(cmd_name, str):
                        command_map[cmd_name] = current_path
            
            # Check commands-data
            if 'commands-data' in chap:
                for cmd in chap['commands-data']:
                    cmd_name = None
                    if isinstance(cmd, str):
                        cmd_name = cmd
                    elif isinstance(cmd, dict):
                        name_obj = cmd.get('name')
                        if isinstance(name_obj, dict):
                            cmd_name = name_obj.get('web')
                        elif isinstance(name_obj, str):
                            cmd_name = name_obj
                    
                    if cmd_name and isinstance(cmd_name, str):
                        command_map[cmd_name] = current_path
                        
            # Recurse
            if 'sub-chapters' in chap:
                traverse(chap['sub-chapters'], current_path)

    if 'chapters' in content_data:
        traverse(content_data['chapters'])
        
    return command_map, ordered_tags
