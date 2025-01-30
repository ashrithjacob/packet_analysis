import subprocess
import json

# The Deno subprocess
deno_process = None


def run_code(string_of_code):
    global deno_process

    try:
        # If the Deno subprocess is not running, start it
        if deno_process is None or deno_process.poll() is not None:
            deno_process = subprocess.Popen(
                ["deno", "run", "--allow-read", "runner.js"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        # Send the code to the Deno subprocess
        deno_process.stdin.write(json.dumps({"code": string_of_code}).encode())
        deno_process.stdin.write("\n".encode())
        deno_process.stdin.flush()

        # Read the result from the Deno subprocess
        output = deno_process.stdout.readline().decode()
        return json.loads(output)
    except Exception as e:
        # If the subprocess crashes, return an error message
        return {"error": str(e)}
