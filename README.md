\# PV NodeJS Layer 7 Load Tester \& HTTP/2 Attack Tool



\*\*pv\_http.js\*\* is a powerful Node.js script for flexible Layer 7 load testing and security auditing of web servers. It automatically detects and utilizes HTTP/1.1, HTTP/2, and HTTP/3, and features multiple operational modes: a standard load test that mimics realistic browser traffic and two distinct HTTP/2 attack modes for resilience checking. With features like randomized TLS profiles, adaptive delays, and detailed real-time monitoring, it is well-suited for stress testing, benchmarking, and protocol security research.



It includes implementations for the following HTTP/2 vulnerabilities:



&nbsp; \* \*\*Rapid Reset Attack\*\* (`--attack rapid-reset`): Exploits CVE-2023-44487 by rapidly opening and canceling streams.

&nbsp; \* \*\*MadeYouReset Attack\*\* (`--attack madeyoureset`): Triggers a server-side stream reset by sending a deliberately oversized data frame, testing protocol error handling.



\# Deflect Bypass ✅

<img width="961" height="300" alt="deflect" src="https://gist.github.com/user-attachments/assets/31c57f3f-98c7-42d4-b19c-6a6e7015f536" />





-----



\## Features



&nbsp; - \*\*Multi-Protocol Support:\*\* Automatically detects and uses HTTP/1.1, HTTP/2, and HTTP/3. Can be forced to use specific protocols.

&nbsp; - \*\*Dual HTTP/2 Attack Modes:\*\* Includes both client-side (`rapid-reset`) and server-side (`madeyoureset`) stream reset attacks.

&nbsp; - \*\*Realistic Traffic Simulation:\*\*

&nbsp;     - Randomizes `User-Agent`, `Referer`, and `Accept` headers from a list of modern browsers.

&nbsp;     - Rotates through distinct TLS profiles (ciphers, sigalgs) to mimic clients like Chrome and Firefox.

&nbsp;     - Sends requests in bursts with randomized "think time" to avoid uniform, robotic patterns.

&nbsp; - \*\*Adaptive Delay:\*\* Optionally enables a backoff mechanism that slows down requests to a target if it returns blocking status codes (e.g., 429 Too Many Requests), then gradually speeds up again.

&nbsp; - \*\*Configurable \& Concurrent:\*\* Control the test duration and number of parallel threads.

&nbsp; - \*\*Real-Time Monitoring:\*\* A colorful, clean CLI dashboard shows live stats including RPS, latency, status code breakdowns per protocol, and a recent event log.

&nbsp; - \*\*Modern \& Performant:\*\* Built with modern Node.js features and the high-performance `undici` HTTP client.



-----



\## Usage



First, install the required dependencies:



```sh

npm install yargs chalk undici

or

npm install yargs@17 chalk@4 undici

```



Then, run the script with a target URL and any desired options:



```sh

node pv\_http.js --url <target-url> \[options]

```



\### Options



| Option | Alias | Description | Default |

| :--- | :--- | :--- | :--- |

| `--url` | `-u` | Target URL (required). | |

| `--time` | `-t` | Test duration in minutes. | `1` |

| `--conc` | `-c` | Concurrency / number of parallel threads. | `50` |

| `--attack` | `-a` | Specify the HTTP/2 attack mode. Choices: `none`, `rapid-reset`, `madeyoureset`. | `none` |

| `--protocol`| `-p` | Force specific protocols, bypassing auto-detection (e.g., "2,3"). | (auto) |

| `--adaptive-delay`| `-ad` | Enable adaptive delay based on blocking status codes (4xx). | `false` |

| `--help` | `-h` | Show help and usage information. | |



-----



\### Example Commands



\#### \*\*Standard Load Test\*\*



A 5-minute load test with 100 concurrent workers, using auto-detected protocols.



```sh

node pv\_http.js -u https://example.com -t 5 -c 100

```



\#### \*\*Force Protocols\*\*



Run a test using only HTTP/1.1 and HTTP/2, splitting concurrency between them.



```sh

node pv\_http.js -u https://example.com --protocol "1.1,2"

```



\#### \*\*Rapid Reset Attack\*\*



Launch the CVE-2023-44487 (Rapid Reset) attack.



```sh

node pv\_http.js -u https://example.com -a rapid-reset

```



\#### \*\*MadeYouReset Attack\*\*



Launch the MadeYouReset attack to trigger server-side resets.



```sh

node pv\_http.js -u https://example.com -a madeyoureset

```



\#### \*\*Test with Adaptive Delay\*\*



Run a standard load test that will automatically slow down if the server starts blocking requests.



```sh

node pv\_http.js -u https://api.example.com --adaptive-delay

```



-----



\## Requirements



&nbsp; - \*\*Node.js\*\* v16 or later.

&nbsp; - \*\*NPM Packages:\*\* `yargs`, `chalk`, `undici`.



-----



\## Legal/Ethics Notice



> \*\*This tool is for educational, research, or authorized security testing on systems you own or have explicit permission to test. Unauthorized use against targets is illegal and unethical. The author is not responsible for misuse.\*\*

