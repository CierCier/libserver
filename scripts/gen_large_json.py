#!/usr/bin/env python3
import json
import random
import string
import sys

# Usage: ./gen_large_json.py [num_objects] [output_file]
NUM_OBJECTS = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
OUTPUT_FILE = sys.argv[2] if len(sys.argv) > 2 else "large.json"

random.seed(42)


def random_string(length=16):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def make_object(idx):
    return {
        "id": idx,
        "name": random_string(12),
        "active": random.choice([True, False]),
        "score": random.uniform(0, 10000),
        "tags": [random_string(6) for _ in range(random.randint(2, 8))],
        "meta": {
            "created": random.randint(1500000000, 1700000000),
            "updated": random.randint(1700000000, 1800000000),
            "owner": random_string(8),
        },
        "payload": random_string(128),
    }


def main():
    with open(OUTPUT_FILE, "w") as f:
        objs = (make_object(i) for i in range(NUM_OBJECTS))
        json.dump(list(objs), f, separators=(",", ":"))
    print(f"Wrote {NUM_OBJECTS} objects to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
