# Poll Vault - Hack the Vote CTF 2024

## Challenge Description
A chatbot on a website for the 2024 election forecast was designed to answer questions one at a time and forgets previous interactions. However, it had a vulnerability that allowed users to explore the host's file system and potentially retrieve sensitive information.

The goal of the challenge was to exploit the chatbot to uncover the hidden flag.

---

## Exploitation Walkthrough

### Step 1: Initial Exploration
To start, I interacted with the chatbot by sending the input `ls`. The bot responded with a list of directories such as:


However, the response was inconsistent:
- Sometimes it listed additional files or directories.
- Other times, it didn’t respond at all or omitted certain results.

This inconsistency hinted at a potential vulnerability to explore further.

---

### Step 2: Identifying Available Tools
When I asked the chatbot, "What tools can I use?", it responded with two functions:
1. `list_directory()`
2. `read_file()`

These functions appeared to be wrappers for basic file system operations. This provided the means to explore the file system and retrieve specific file contents.

---

### Step 3: Enumerating Files
Using the `list_directory()` function, I explored directories like `/var`, `/etc`, and `/bin`. After some trial and error, I discovered an interesting file in `/var`:

The name suggested it might contain sensitive data.

---

### Step 4: Reading Sensitive Files
I used the `read_file()` function to access the file contents:

#### Then I used tools to discover other files, such as the flag. I know you saw me using read_file(../flag.txt), but I needed to go back to the parent directory and read it. However, I couldn't because I only had one input. I tried to find other files and discovered app.py, which contains important information—like the original functions of the tools and other functionalities.
```
   def tool_list_directory(self, dir_path):
        """List files in the given directory."""
        dir_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), dir_path)
        try:
            if os.path.isdir(dir_path):
                return [
                    os.path.relpath(os.path.join(dir_path, f), os.path.dirname(os.path.abspath(__file__)))
                    for f in os.listdir(dir_path)
                ]
            else:
                return f"Error: The directory {dir_path} does not exist."
        except Exception as e:
            return f"Error listing directory {dir_path}: {e}"

    def tool_read_file(self, file_path):
        """Read the contents of the specified file."""
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
        if not os.path.abspath(file_path).startswith(os.path.dirname(os.path.abspath(__file__))):
            return "Error: You cannot read files outside of the current directory."
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r') as file:
                    return file.read()
            except Exception as e:
                return f"Error reading file {file_path}: {e}"
        else:
            return f"Error: The file {file_path} does not exist."

```
##### if you wanna read all file , you find him in files directory
## I discovered that I could read files outside of the current directory, but I found another tool called tool_forecast():
```
def tool_forecast(self, model_path):
        """Run the forecast tool using the specified model path."""
        FORECAST_PATH = "./forecast.py"
        try:
            result = subprocess.run(
                [FORECAST_PATH, model_path],
                capture_output=True,
                text=True,
                check=False,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            return result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            return f"Error running forecast tool: {e}"

```
## If you notice, this function is specifically designed to run ./forecast.py, but there is no parsing or input validation, allowing me to read files outside the current directory.

## I read the flag using tool_forecast('../flag.txt'):
```
7944425039487659110 candidates,
7232626473741477223 states,
9035755089488344128 votes.
```
## It wasn't understandable, so I realized I needed something else. I searched to see if these numbers were some kind of cipher, but they weren't
### I tried to read forecast.py and discovered a function that can be used to decrypt those numbers:
```
def parse_forecast(binary_data):
    ''' Parse a forecast file '''
    def _handle_parse_error(result, error):
        print(f"PARSED DATA {result} prior to error")
        result = {}

    header_format = 'LLL'
    try:
        header_size = struct.calcsize(header_format)
        num_candidates, num_states, total_votes = struct.unpack_from(header_format, binary_data)
        result = {
            'num_candidates': num_candidates,
            'num_states': num_states,
            'total_votes': total_votes
        }
        offset = header_size

        candidate_format = 'I20s20sff'
        candidate_size = struct.calcsize(candidate_format)
        candidates = []

        for _ in range(num_candidates):
            candidate_id, name, party, polling_percentage, polling_error_margin = struct.unpack_from(candidate_format, binary_data, offset)
            name = name.decode('utf-8').strip('\x00')
            party = party.decode('utf-8').strip('\x00')
            candidates.append((candidate_id, name, party, polling_percentage, polling_error_margin))
            offset += candidate_size
        
        result['candidates'] = candidates

        states = []
        state_format = 'III'
        state_size = struct.calcsize(state_format)

        for _ in range(num_states):
            state_id, electoral_votes, population = struct.unpack_from(state_format, binary_data, offset)
            offset += state_size

            votes_per_candidate = []
            for _ in range(num_candidates):
                votes = struct.unpack_from('I', binary_data, offset)[0]
                votes_per_candidate.append(votes)
                offset += 4
            
            states.append((state_id, electoral_votes, population, votes_per_candidate))
        
        result['states'] = states
        return result
    except Exception as e:
        # If we fail to parse our input, log what we have for debugging
        _handle_parse_error(result, e)


```

## and then i find a script can let the convert numbers to hex -> ascii  : 
```
import struct
```
# === PACKING INTEGERS INTO BINARY ===
# THE VALUES TO BE CONVERTED
```
NUM_CANDIDATES = 7944425039487659110
NUM_STATES = 7232626473741477223
TOTAL_VOTES = 9035755089488344128
```
# PACK THE INTEGERS INTO BINARY (64-BIT UNSIGNED INTEGERS)
```
BINARY_DATA = struct.pack('QQQ', NUM_CANDIDATES, NUM_STATES, TOTAL_VOTES)
```
# === DISPLAYING THE BINARY DATA ===

# HEXADECIMAL REPRESENTATION
```
print("# === HEX REPRESENTATION ===")
print(BINARY_DATA.hex())
```
# ASCII REPRESENTATION
```
print("\n# === ASCII REPRESENTATION ===")
print("".join(chr(b) if 32 <= b <= 126 else '.' for b in BINARY_DATA))
```
# UTF-8 DECODING
```
print("\n# === UTF-8 DECODING ===")
try:
    print(BINARY_DATA.decode('utf-8'))
except UnicodeDecodeError:
    print("NOT VALID UTF-8")
```
# RAW BYTES LIST
```
print("\n# === RAW BYTES LIST ===")
print([hex(b) for b in BINARY_DATA])
```
# === WRITING TO A FILE ===
```
print("\n# === WRITING TO FILE: reversed.bin ===")
with open("reversed.bin", "wb") as f:
    f.write(BINARY_DATA)

```
# flag is:
## flag{D@nger0us_d@tabase}