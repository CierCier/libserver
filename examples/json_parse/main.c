#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <map.h>

static void print_value(const struct JsonValue *v, const char *label) {
	char *s = json_serialize(v);
	if (s) {
		printf("%s: %s\n", label, s);
		free(s);
	} else {
		printf("%s: <serialize failed>\n", label);
	}
}

int main(int argc, char **argv) {
	const char *filename = argc > 1 ? argv[1] : "large.json";
	FILE *f = fopen(filename, "rb");
	if (!f) {
		fprintf(stderr, "Failed to open %s\n", filename);
		return 1;
	}
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buf = malloc(sz + 1);
	if (!buf) {
		fprintf(stderr, "Out of memory\n");
		fclose(f);
		return 1;
	}
	fread(buf, 1, sz, f);
	buf[sz] = '\0';
	fclose(f);

	printf("Parsing %s (size: %ld bytes)\n", filename, sz);
	struct JsonValue *root = json_parse(buf);
	free(buf);
	if (!root) {
		printf("Parse failed!\n");
		return 1;
	}

	if (json_is_array(root)) {
		size_t n = json_get_array_size(root);
		printf("Top-level array with %zu objects\n", n);
		if (n > 0) {
			struct JsonValue *first = json_get_array_element(root, 0);
			struct JsonValue *last = json_get_array_element(root, n - 1);
			print_value(first, "First object");
			print_value(last, "Last object");
		}
	} else if (json_is_object(root)) {
		printf("Top-level object\n");
		print_value(root, "Root object");
	} else {
		printf("Top-level value is not array or object\n");
		print_value(root, "Root value");
	}

	json_free(root);
	return 0;
}
