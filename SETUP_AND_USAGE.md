# RECON Setup and Usage

Complete guide to building and running RECON.

---

## Prerequisites

### Required Software

1. **Java Development Kit (JDK) 11 or higher**
   - Download: https://adoptium.net/
   - Verify: `java -version`

2. **Apache Maven 3.6+**
   - Download: https://maven.apache.org/download.cgi
   - Verify: `mvn -version`

3. **Android SDK**
   - Download: https://developer.android.com/studio
   - Need the `platforms/` directory

**Typical Android SDK locations:**
- Linux/Mac: `~/Android/Sdk/platforms/`
- Windows: `C:\Users\<username>\AppData\Local\Android\Sdk\platforms\`

---

## Building RECON

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/RECON.git
cd RECON
```

### Step 2: Build

**Quick Build (Skip Tests)**
```bash
mvn clean install -DskipTests
```
*Takes ~5-10 minutes*

**Full Build (With Tests)**
```bash
# Requires: JDK 8, ANDROID_JARS env variable, DroidBench
export ANDROID_JARS=$HOME/Android/Sdk/platforms/
mvn clean install
```
*Takes ~30-40 minutes*

### Step 3: Verify Build

```bash
ls soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar
```

You should see the JAR file created.

---

## Configuration

### Android SDK Path

Set the `ANDROID_JARS` environment variable:

**Linux/Mac:**
```bash
export ANDROID_JARS=$HOME/Android/Sdk/platforms/

# Make permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export ANDROID_JARS=$HOME/Android/Sdk/platforms/' >> ~/.bashrc
```

**Windows:**
```powershell
$env:ANDROID_JARS="C:\Users\YourName\AppData\Local\Android\Sdk\platforms\"
```

### Dangerous APIs Configuration

RECON uses `dangerous_apis.json` to define which Android APIs to analyze.

**Location:** Project root or `config/dangerous_apis.json`

**Sample Format:**
```json
{
  "categories": {
    "dynamic_code_loading": {
      "severity": "HIGH",
      "description": "Dynamic code loading",
      "apis": [
        "dalvik.system.DexClassLoader: void <init>(...)",
        "java.lang.Runtime: java.lang.Process exec(...)"
      ]
    }
  }
}
```

---

## Running RECON

### Basic Command

```bash
java -jar soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar \
    -a <APK_FILE> \
    -p $ANDROID_JARS \
    -s <SOURCES_SINKS_FILE>
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-a <file>` | APK file to analyze |
| `-p <dir>` | Android SDK platforms directory |
| `-s <file>` | Sources and sinks definition file |
| `-o <file>` | Output file (optional) |
| `-dt <sec>` | Analysis timeout (optional) |

### Sources and Sinks File

Use the default file from FlowDroid:
```
soot-infoflow-android/SourcesAndSinks.txt
```

---

## Example Usage

### Example 1: Single APK Analysis

```bash
# Set Android SDK path
export ANDROID_JARS=$HOME/Android/Sdk/platforms/

# Analyze APK
java -jar soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar \
    -a samples/app.apk \
    -p $ANDROID_JARS \
    -s soot-infoflow-android/SourcesAndSinks.txt
```

### Example 2: With Timeout

```bash
java -jar soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar \
    -a samples/app.apk \
    -p $ANDROID_JARS \
    -s soot-infoflow-android/SourcesAndSinks.txt \
    -dt 600
```

### Example 3: Large APK (More Memory)

```bash
java -Xmx16g -jar soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar \
    -a large_app.apk \
    -p $ANDROID_JARS \
    -s soot-infoflow-android/SourcesAndSinks.txt
```

---

## Understanding Output

### Output Directory Structure

```
results/
└── <APK_HASH>/
    ├── analysis_summary.json
    ├── dangerous_apis_found.json
    ├── constraint_analysis/
    │   ├── <method>_<category>.json
    │   └── <method>_<category>_summary.txt
    └── llm_interactions/
        └── <timestamp>.json
```

### Key Output Files

**1. dangerous_apis_found.json**
```json
{
  "dynamic_code_loading": [
    {
      "signature": "dalvik.system.DexClassLoader: void <init>(...)",
      "severity": "HIGH",
      "call_chains": [...],
      "constraints": [...]
    }
  ]
}
```

**2. Constraint Analysis**

Each dangerous API gets detailed analysis:
- JSON file with extracted constraints
- Summary text file with human-readable constraints

---

## Performance Tuning

### Faster Analysis

```bash
# Skip static field tracking
-ns

# Skip exceptional flows
-ne

# Reduce callback depth
-md 3
```

### More Precision

```bash
# Enable path reconstruction
-pr precise

# Increase access path length
-al 10

# Better callgraph
-cg SPARK
```

---

## Troubleshooting

### Out of Memory

```bash
java -Xmx16g -jar soot-infoflow-cmd-jar-with-dependencies.jar ...
```

### Android SDK Not Found

```bash
# Verify path
echo $ANDROID_JARS
ls $ANDROID_JARS
```

### Build Failures

```bash
# Clean and rebuild
mvn clean
mvn install -DskipTests
```

### Analysis Timeout

```bash
# Increase timeout
-dt 3600  # 1 hour
```

---

## Complete Example

```bash
# 1. Setup
export ANDROID_JARS=$HOME/Android/Sdk/platforms/

# 2. Clone and build
git clone https://github.com/yourusername/RECON.git
cd RECON
mvn clean install -DskipTests

# 3. Run analysis
java -Xmx8g -jar soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar \
    -a samples/app.apk \
    -p $ANDROID_JARS \
    -s soot-infoflow-android/SourcesAndSinks.txt \
    -dt 600

# 4. Check results
ls results/
cat results/*/dangerous_apis_found.json
```

---

## Evaluation Framework

RECON includes a Python evaluation framework in `evaluation/`:

```bash
cd evaluation/

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run evaluation
python run_evaluation.py
```

See `evaluation/README.md` for details.

---

## Additional Options

For all FlowDroid options, run:
```bash
java -jar soot-infoflow-cmd-jar-with-dependencies.jar --help
```

---

**RECON Version**: 1.0  
**FlowDroid Base**: v2.14.1
