def build_schema_from_object(obj_def, objects_map):
    properties = {}
    required = []
    
    # Process regular fields
    if 'fields' in obj_def:
        for field in obj_def['fields']:
            _process_field(field, properties, required)

    # Process required-fields
    if 'required-fields' in obj_def:
        for field in obj_def['required-fields']:
            # Treat as regular field for now
             _process_field(field, properties, required_list=None)

    # Process under-more-fields
    if 'under-more-fields' in obj_def:
        for field in obj_def['under-more-fields']:
             _process_field(field, properties, required_list=None)

    return {
        "type": "object",
        "properties": properties,
        # "required": required 
    }

def _process_field(field, properties, required_list=None):
    field_name = field['name']
    field_desc = field.get('description', '')
    
    # Determine type and enum
    field_type = 'string'
    enum_values = None
    items_schema = None
    
    if 'types' in field and len(field['types']) > 0:
        # Check for list type first (prioritize array)
        list_type = next((t for t in field['types'] if t['name'] == 'list'), None)
        if list_type:
            field_type = 'array'
            # Try to get element type
            if 'element-type' in list_type:
                elem_type_name = list_type['element-type'].get('name', 'string')
                items_schema = {"type": "string"} # Default item type
                if elem_type_name == 'integer':
                     items_schema = {"type": "integer"}
                elif elem_type_name == 'boolean':
                     items_schema = {"type": "boolean"}
        else:
            # If not list, take the first type (usually string, integer, boolean)
            first_type = field['types'][0]
            type_name = first_type['name']
            
            if type_name == 'integer':
                field_type = 'integer'
            elif type_name == 'boolean':
                field_type = 'boolean'
            
            # Check for enums
            if 'valid-values' in first_type:
                enum_values = first_type['valid-values']

    prop_schema = {
        "type": field_type,
        "description": field_desc
    }
    
    if enum_values:
        prop_schema['enum'] = enum_values
        
    if field_type == 'array':
        prop_schema['items'] = items_schema if items_schema else {"type": "string"}

    properties[field_name] = prop_schema
    
    if required_list is not None and field.get('required', False):
        required_list.append(field_name)
