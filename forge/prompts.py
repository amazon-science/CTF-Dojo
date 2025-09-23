# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: CC-BY-NC-4.0

# Prompt templates and related large string constants extracted from ctf_forge.py

SERVER_DETECTION_PROMPT = '''Based on the following CTF challenge information, determine if this challenge requires a server/service to be running.

# Challenge Name:
{task_name}

# Challenge Category:
{category}

# Challenge Description: 
{description}

# REHOST.md Content:
{rehost_content}

# Available Files:
{available_files_info}

# File Analysis:
{file_analysis}

# Has SHA256 File:
{has_sha256_file}

Based on the available files and enhanced file analysis, determine if this challenge can be hosted on a server.
Note that the executable binary can be used to host a server, like containerizing it in the Docker environment.

IMPORTANT RULES:
1. If the CTF challenge has its own custom flag mentioned in the REHOST.md content, respond with "NO" as no server is needed.
2. If the challenge category is "rev" (reverse engineering), respond with "NO" as these challenges are always file-based and never need servers.
3. If the REHOST.md content mentions that files read the flag from "/flag" in the environment, respond with "YES" as this indicates the challenge needs to run in a containerized server environment.
4. Consider the file analysis to determine if files suggest a server-based challenge:
   - Executable files often indicate server-hosted challenges (pwn, networking)
   - Web files (HTML, PHP, CSS, JS) typically require web servers
   - Script files (Python, JavaScript, etc.) may need server hosting
   - Multiple files in a project structure often benefit from server hosting
5. If you think that the CTF players should access the challenge files locally based on the REHOST.md content and the challenge category, respond with "NO" as no server is needed.
6. Otherwise, think step by step and respond with "YES" if the challenge can be run on a server, or "NO" if it's not needed.
7. If there is a way to use Dockerfile and Docker-compose to host the challenge file on an internet server inside the container, respond with "YES".

Analyze the file types and structure to make an informed decision about server requirements.'''

DOCKERFILE_GENERATION_PROMPT = '''Based on the following CTF challenge information, generate a Dockerfile that will properly set up a server environment for CTF players to interact with.

# Challenge Name:
{task_name}

# Challenge Category:
{category}

# Available Files:
{available_files}

# File Analysis:
{file_analysis}

# Challenge Description:
{description}

# REHOST.md Content:
{rehost_content}

# .init File Content:
{init_content}

**IMPORTANT**: If .init file content is provided above, this contains setup instructions or configuration specific to this challenge. The .init file may contain:
- Environment setup commands that should be executed during Docker build
- Configuration parameters or paths that should be used in the Dockerfile
- Special instructions for handling this particular challenge
- Library or dependency information
- Runtime configuration that affects how the challenge should be containerized

Use the .init content to inform your Dockerfile generation - execute any setup commands it specifies, copy any files it references, and follow any special instructions it provides.

{flag_instruction}

# CATEGORY-SPECIFIC GUIDELINES:
{category_guidelines}

# GENERAL DOCKER BEST PRACTICES:
1. Use ubuntu:20.04 as base image unless challenge specifically requires different environment
2. Install additional packages needed for the specific challenge (if any beyond the comprehensive set)
3. Create non-root user for running services when possible, but DO NOT use `useradd`
4. Use specific package versions when critical for challenge functionality
5. Properly set file permissions (especially for executables and sensitive files)
6. Use WORKDIR to organize files properly
7. Expose only the necessary port for the challenge
8. Use specific CMD/ENTRYPOINT that matches the challenge type
9. You MUST create a `run.sh` wrapper script using printf or echo commands (DO NOT use heredoc syntax like << 'EOF')
10. If `.init` file is provided and you tend to run it in the Dockerfile, you MUST use `RUN`  with `|| true` to avoid build failure

# CRITICAL SCRIPT CREATION SYNTAX:
- CORRECT: Use printf to create shell scripts in Dockerfiles:
  ```
  RUN printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 ./your_executable\\n' > /challenge/run.sh
  ```
- CORRECT: Use echo with \\n for newlines:
  ```
  RUN echo -e '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 ./your_executable' > /challenge/run.sh
  ```
- WRONG: Never use heredoc syntax in Dockerfiles (causes parsing errors):
  ```
  RUN cat > /challenge/run.sh << 'EOF'  # This will FAIL
  #!/bin/bash
  cd /challenge
  exec stdbuf -i0 -o0 -e0 ./your_executable
  EOF
  ```

# CRITICAL EXECUTABLE/SCRIPT WRAPPING REQUIREMENTS:
{architecture_specific_wrapper}

# SECURITY CONSIDERATIONS:
- DO NOT copy flag.sha256 or flagcheck files to the Docker image
- DO NOT copy any files not in the available files list
- Set appropriate file permissions for challenge files
- Use process isolation when running network services

# SHEBANG HANDLING:
- If any files have problematic shebangs (like #!/opt/pwn.college/python), they will be automatically fixed
- You do not need to manually handle shebang issues - the system will detect and fix them
- Focus on proper file copying and permissions

# CTF-SPECIFIC REQUIREMENTS:
- The server MUST be accessible to CTF players over the network
- The flag should NEVER be directly accessed by the CTF players, and MUST always be stored in /flag with the permissions 444
- Choose appropriate port based on service type (1337 for general, 80/8080 for web, etc.)
- Ensure the challenge service starts automatically and runs continuously
- Handle connection multiplexing for multiple players if needed
- Programs must respond to user input immediately without buffering delays (achieved through stdbuf)

# CRITICAL CTF BINARY BEHAVIOR UNDERSTANDING:
- CTF challenge binaries (especially pwn challenges) often exhibit specific behavior patterns:
  * When run directly from command line, they may exit immediately without output (THIS IS NORMAL)
  * They are designed to work through network services (socat) that provide stdin/stdout redirection
  * The binary may wait for specific input patterns or network connections to respond
  * Some binaries are designed to read from stdin and write to stdout in an interactive manner
- Do NOT assume a binary is broken if it runs without output when executed directly
- The key is to properly wrap the binary with socat for network access
- Test the service through network connection (nc localhost PORT) rather than direct execution

# LIBRARY DEPENDENCY HANDLING:
- Pay special attention to shared library dependencies (check with ldd if needed conceptually)
- For 32-bit binaries on 64-bit systems, ensure 32-bit libraries are installed
- If a binary requires specific libraries (e.g., libpam.so.0), install the appropriate packages:
  * For libpam: install libpam0g:i386 for 32-bit or libpam0g for 64-bit
  * Use library path environment variables or LD_LIBRARY_PATH if needed
  * Consider using the system's dynamic linker directly for better compatibility

Generate a complete, production-ready Dockerfile. Respond with ONLY the Dockerfile content, no explanations.

IMPORTANT VALIDATION CHECKLIST:
□ Base image specified (prefer ubuntu:20.04)
□ NOTE: Comprehensive package installation will be automatically added
□ Additional required packages installed (if needed beyond the comprehensive set)
□ Challenge files copied correctly
□ run.sh wrapper script created with stdbuf for proper interaction
□ Appropriate port exposed
□ Service command specified in CMD/ENTRYPOINT using socat with the run.sh wrapper
□ File permissions set correctly for both executables and run.sh
□ No sensitive files copied
□ Service will accept network connections and respond immediately to user input
□ CRITICAL: Scripts created using printf/echo commands, NOT heredoc syntax (<<)

# ⚠️  CRITICAL DOCKERFILE SYNTAX WARNING:
- NEVER use heredoc syntax like "RUN cat > file << 'EOF'" in Dockerfiles
- This causes Docker parsing errors and build failures
- ALWAYS use printf or echo commands instead
- Example: RUN printf '#!/bin/bash\\ncd /challenge\\nexec ./binary\\n' > /challenge/run.sh

# PYTHON NETWORK SERVICES:
- If the file analysis indicates a Python script is a network server listening on a specific internal port (e.g., detected as listening on port XXXX):
- The service MUST be run in the background (e.g., `python3 /challenge/server.py &`).
- You MUST use `socat` to proxy connections from the public EXPOSED port (e.g., 1337) to the script's detected internal port.
- **CORRECT WAY** to create `run.sh` for a Python server on its detected internal port, exposed on 1337:
  ```
  RUN printf '#!/bin/sh\\ncd /challenge\\n# Start the server in the background\\npython3 /challenge/server.py &\\n# Wait a moment for the server to start\\nsleep 1\\n# Use socat to forward connections from the public port to the internal port\\nexec socat TCP-LISTEN:1337,reuseaddr,fork TCP:localhost:XXXX\\n' > /challenge/run.sh && chmod +x /challenge/run.sh
  ```
- The `CMD` in the Dockerfile should then be `CMD ["/challenge/run.sh"]`.
- DO NOT use `socat` with `EXEC` for these types of services, as it launches a new process for every connection.'''

WRAPPER_32BIT = '''- **MANDATORY**: ALL executable files (binaries, scripts, etc.) MUST be wrapped with a run.sh script to run via socat
- **MANDATORY**: For 32-bit binaries, use custom stdbuf32 command to avoid architecture mismatch
- This ensures CTF players can interact with the running programs exactly like running them locally
- **CORRECT WAY** to create wrapper script in Dockerfile:
  ```
  RUN printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf32 -i0 -o0 -e0 linux32 ./your_executable\\n' > /challenge/run.sh && chmod +x /challenge/run.sh
  ```
- **IMPORTANT**: If binary has library dependency issues, consider using the dynamic linker directly:
  ```
  RUN printf '#!/bin/sh\\ncd /challenge\\nexec /lib/ld-linux.so.2 --library-path /lib/i386-linux-gnu:/usr/lib/i386-linux-gnu:/challenge ./binary_name\\n' > /challenge/run.sh && chmod +x /challenge/run.sh
  ```
- For Python scripts: Use `printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 python3 ./script.py\\n' > /challenge/run.sh` (scripts can use regular stdbuf)
- For Node.js scripts: Use `printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 node ./script.js\\n' > /challenge/run.sh` (scripts can use regular stdbuf)
- For 32-bit binary executables: Use `printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf32 -i0 -o0 -e0 linux32 ./binary_name\\n' > /challenge/run.sh`
- For shell scripts: Use `printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 /bin/bash ./script.sh\\n' > /challenge/run.sh` (scripts can use regular stdbuf)
- Always use `exec` to replace the shell process and `cd /challenge` to ensure proper working directory
- Always chmod +x the run.sh script after creating it
- Then use socat to host the service: `CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/challenge/run.sh"]`
- NOTE: stdbuf32 is a custom wrapper that provides unbuffered I/O for 32-bit binaries without ELF class conflicts
- **LIBRARY PATH**: If binary requires specific libraries, ensure proper library path setup in the wrapper script'''

WRAPPER_64BIT = '''- **MANDATORY**: ALL executable files (binaries, scripts, etc.) MUST be wrapped with a run.sh script to run via socat
- **MANDATORY**: Use `stdbuf -i0 -o0 -e0` in the run.sh wrapper to disable buffering for proper CTF player interaction
- This ensures CTF players can interact with the running programs exactly like running them locally
- **CORRECT WAY** to create wrapper script in Dockerfile:
  ```
  RUN printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 ./your_executable\\n' > /challenge/run.sh && chmod +x /challenge/run.sh
  ```
- For Python scripts: Use `printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 python3 ./script.py\\n' > /challenge/run.sh`
- For Node.js scripts: Use `printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 node ./script.js\\n' > /challenge/run.sh`
- For binary executables: Use `printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 ./binary_name\\n' > /challenge/run.sh`
- For shell scripts: Use `printf '#!/bin/bash\\ncd /challenge\\nexec stdbuf -i0 -o0 -e0 /bin/bash ./script.sh\\n' > /challenge/run.sh`
- Always use `exec` to replace the shell process and `cd /challenge` to ensure proper working directory
- Always chmod +x the run.sh script after creating it
- Then use socat to host the service: `CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/challenge/run.sh"]`'''

DOCKER_COMPOSE_GENERATION_PROMPT = '''Based on the following CTF challenge information and generated Dockerfile, create a docker-compose.yml file with an appropriate ctfnet alias.

# Challenge Name:
{task_name}

# CTF Name:
{ctf_name}

# Available Files:
{available_files}

# Challenge Description:
{description}

Generated Dockerfile:
{dockerfile_content}

Requirements:
1. Use "build: ." to build from the local Dockerfile
2. Extract the exposed port from the Dockerfile and map it appropriately
3. Connect to the "ctfnet" external network
4. Generate a meaningful, DNS-compliant alias for this specific challenge
5. The alias should be memorable and related to the challenge name/theme
6. Use format like: challengename.ctf.io or similar creative naming
7. Avoid generic names like "web.chal.custom.io"
8. Use the challenge information to create a relevant alias

Example good aliases:
- showdown.csaw.io
- cryptochallenge.picoctf.io  
- webshell.defcon.io
- bufferoverflow.ctf.io

Generate a complete docker-compose.yml. Respond with ONLY the docker-compose.yml content, no explanations.'''

CHALLENGE_JSON_PROMPT = '''Generate a challenge.json file for this CTF challenge following the exact schema.

Challenge Information:
# Name:
{task_name}

# Category:
{category}

# Files:
{task_files}

# CTF Challenge RAW Description:
{description}

# REHOST.md Content:
{rehost_content}

{docker_compose_section}

REQUIRED JSON SCHEMA:
{{
    "name": "challenge name",
    "description": "human readable and self-contained challenge description for the CTF players, not for the CTF rehosters. flag checker is NOT available and you should NOT mention it in the description",
    "category": "will be set automatically from module.yml mapping",
    "files": ["list of files to upload for this challenge"],
    "box": "optional URL for external server challenge",
    "internal_port": "optional port for external server challenge",
    "compose": true if hosting the ctf challenge requires a server, false otherwise,
    "flag": "flag for the challenge"
}}

RULES:
1. Use the exact challenge name: "{task_name}"
2. Use the exact files list: {task_files}
3. DO NOT generate the category field - it will be set automatically from module.yml mapping
4. Always set "box": "" and "internal_port": ""
5. If server_needed is False: do NOT include "server_description" field
6. The flag should be a valid flag for the challenge
7. You MUST NOT mention the flagCheck in the Challenge Description, as we will handle the validation in other way.

OUTPUT: Return ONLY valid JSON matching the schema above. No explanations, no markdown, no extra text.'''
