#include <jansson.h>
#include <stdio.h>
#include <yara/modules.h>

#define MODULE_NAME json


define_function(key_value) {
    YR_SCAN_CONTEXT* context = scan_context();
    YR_MEMORY_BLOCK* block = first_memory_block(context);
    uint8_t* block_data = block->fetch_data(block);

    json_error_t json_error;
    json_t* json = json_loads((const char*) block_data, 0, &json_error);

    if (json == NULL) {
        printf("\nFailed to load JSON: %s (line: %i, col: %i, pos: %i)\n", json_error.text, json_error.line, json_error.column, json_error.position);
        return ERROR_INVALID_FILE;
    }

    char* key = string_argument(1);
    char* value = string_argument(2);

    json_t* json_value = json_object_get(json, key);
    if (json_value == NULL) {
        return_integer(UNDEFINED);
    }

    const char* json_val = json_string_value(json_value);
    if (strcmp(json_val, value) == 0) {
        return_integer(1);
    }

    return_integer(0);
}

begin_declarations;

    declare_function("kv", "ss", "i", key_value);

end_declarations;


int module_initialize(YR_MODULE* module) {
    return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module) {
    return ERROR_SUCCESS;
}


int module_load(YR_SCAN_CONTEXT* context, YR_OBJECT* module_object, void* module_data, size_t module_data_size) {
    return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object) {
    return ERROR_SUCCESS;
}


