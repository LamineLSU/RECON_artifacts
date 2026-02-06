# RECON: An LLM-Enhanced Backward Constraint Analysis Framework

RECON is an LLM-enhanced backward constraint analysis framework for extracting execution constraints from Android bytecode.

This project extends [FlowDroid](https://github.com/secure-software-engineering/FlowDroid) v2.14.1.

---

## Quick Start

### Prerequisites

- JDK 11 or higher
- Maven 3.6+
- Android SDK platforms directory

### Build

```bash
git clone https://github.com/yourusername/RECON.git
cd RECON
mvn clean install -DskipTests
```

### Run

```bash
export ANDROID_JARS=/path/to/android-sdk/platforms

java -jar soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar \
    -a sample.apk \
    -p $ANDROID_JARS \
    -s SourcesAndSinks.txt
```

See [SETUP_AND_USAGE.md](SETUP_AND_USAGE.md) for detailed instructions.

---

## Repository Structure

```
RECON/
├── soot-infoflow/                     # FlowDroid core (unchanged)
├── soot-infoflow-android/             # Android support (unchanged)
├── soot-infoflow-summaries/           # Method summaries (unchanged)
├── soot-infoflow-cmd/                 # ⭐ Our modifications
│   └── src/soot/jimple/infoflow/cmd/
│       ├── BackwardConstraintAnalyzer.java
│       ├── ConstraintExtractor.java
│       └── [17 more files]
├── evaluation/                        # ⭐ Python evaluation framework
└── config/                            # ⭐ Configuration files
```

---

## License

Licensed under LGPL v2.1 (same as FlowDroid).

---

**Base Version**: FlowDroid v2.14.1  
**Original Repository**: https://github.com/secure-software-engineering/FlowDroid
