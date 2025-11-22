#include "json.h"
#include <stdio.h>

int main() {
    printf("Creating null json value...\n");
    struct JsonValue *null_val = json_create_null();
    
    printf("Freeing null json value...\n");
    // This should crash because null_val is a pointer to a static variable
    json_free(null_val);
    
    printf("Success (should not be reached)\n");
    return 0;
}
