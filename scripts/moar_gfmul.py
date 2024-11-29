#!/bin/python3
import json
import base64
from secrets import token_bytes

def generate_testcase(name, semantic):
    return {
        name: {
            "action": "gfmul",
            "arguments": {
                "semantic": semantic,
                "a": base64.b64encode(token_bytes(16)).decode(),
                "b": base64.b64encode(token_bytes(16)).decode()
            }
        }
    }

def generate_testcases(count=10):
    testcases = {}
    for i in range(count):
        for semantic in ["xex", "gcm"]:
            name = f"gfmul_{semantic}_random_{i}"
            testcases.update(generate_testcase(name, semantic))
    return {"testcases": testcases}

def write_testcases(filename="testcases.json"):
    data = generate_testcases(2000)
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    write_testcases()
